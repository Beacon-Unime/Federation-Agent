import json
import logging
import requests
import inspect
import hashlib

from ryu.base import app_manager
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from requests.auth import HTTPBasicAuth
from ryu.exception import RyuException
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu import cfg
from ryu import utils
from ryu.lib.packet.packet import Packet
from ryu.ofproto import nx_match
import ryu.lib.ovs.vsctl as ovs_vsctl
from ryu.app.rest_router import ( ip_addr_aton,
                                  ip_addr_ntoa,
                                  mask_ntob,
                                  ipv4_apply_mask,
                                  ipv4_int_to_text,
                                  ipv4_text_to_int,
                                  nw_addr_aton,
                                  ip_addr_aton )
from netfa.fa_sdn_controller import EventRegisterVNIDReq
from netfa.fa_sdn_controller import EventRegisterVNIDReply
from netfa.fa_sdn_controller import EventLocationReq
from netfa.fa_sdn_controller import EventLocUpdateReq
from netfa.fa_sdn_controller import FaSdnController
from jsonschema import validate

dove_fa_api_instance_name = 'dove_fa_api_app'
url_tenants = '/dove-fa/tenants'

TENANTID_PATTERN = r'[0-9a-f]{32}'

class DoveFaSwitch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_2]
    _CONTEXTS = { 'wsgi': WSGIApplication }
    _EVENTS=[EventRegisterVNIDReq]

    def __init__(self, *args, **kwargs):
        super(DoveFaSwitch, self).__init__(*args, **kwargs)
        self.switch = {}
        self.vsctl = ovs_vsctl.VSCtl('unix:/usr/local/var/run/openvswitch/db.sock')
        wsgi = kwargs['wsgi']
        wsgi.register(DoveFaApi, {dove_fa_api_instance_name : self})
        self.CONF.register_opts([
            cfg.StrOpt('my_site', default='site1'),
            cfg.StrOpt('fa_br_name', default='br-fa'),
            cfg.StrOpt('fa_tun_name', default='fa-tun')
            ])

#     def rest_client(self, switch):
#         print ("Enter rest %s" % switch)
#         #switch.dcs = self.get_dcs() XXX

#         while True:
#             if len(switch.switches) < 1:
#                 raise RyuException(msg="FA needs br-fa datapath")

#             print "Woke up"
#             for datapath_id,sw in switch.switches.items():
#                 print datapatth_id
#                 print switch
#                 print "\n"

#                 if sw['dmc'] == None:
#                     dmc = self.dmc_registration(datapath_id)
#                     print dmc
#                     if dmc:
#                         sw['dmc'] = dmc

#                 if sw['dmc'] != None:
#                     print sw['dmc']
#                     self.dmc_hb(sw['dmc'])

#             hub.sleep(self.DMC_HB_INTERVAL)

#     def dmc_hb(self, dmc):
#         auth = HTTPBasicAuth('admin', 'admin')
#         headers = {'content-type': 'application/json', 'Accept': 'application/json', 'charsets': 'utf-8'}
#         r = requests.put('http://' + self.CONF.dmc_url + '/controller/sb/v2/opendove/odmc/switch/%s' % dmc['id'] , headers=headers, auth=auth,
#                           data=json.dumps( {"id": str(dmc['id']),
#                                             "name": str(dmc['name']),
#                                             "tunnelip": str(dmc['tunnelip']),
#                                             "managementip": str(dmc['managementip'])}))

#     def dmc_registration(self, id):
#         auth = HTTPBasicAuth('admin', 'admin')
#         headers = {'content-type': 'application/json', 'Accept': 'application/json', 'charsets': 'utf-8'}
#         r = requests.post('http://' + self.CONF.dmc_url + '/controller/sb/v2/opendove/odmc/switch', headers=headers, auth=auth,
#                           data=json.dumps({'id': 'null', 'name': str(id), 'tunnelip': "127.0.0.1", 'managementip': '127.0.0.1'}))

#         if int(r.status_code) == 201:
#             sw = r.json()
#             return sw
#         else:
#             return None

#     def get_dcs(self):
#         auth = HTTPBasicAuth('admin', 'admin')
#         headers = {'content-type': 'application/json', 'Accept': 'application/json', 'charsets': 'utf-8'}
#         r = requests.get('http://' + self.CONF.dmc_url + '/controller/sb/v2/opendove/odmc/odcs/leader', headers=headers, auth=auth)

#         if(r.status_code != 200):
#             raise RyuException(msg="Error getting DCS address")

#         res = json.loads(r.text)
#         return {'ip': res['ip'], 'port': res['dcs_raw_service_port']}

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def state_change_handler(self, ev):

        if not ev.state == 'config': return

        dp = ev.datapath
        ofproto = dp.ofproto

        dp.send_nxt_set_flow_format(ofproto_v1_0.NXFF_NXM)

        set_format = dp.ofproto_parser.NXTSetPacketInFormat(dp, ofproto.NXPIF_NXM)
        dp.send_msg(set_format)
        dp.send_barrier()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print ev.msg
        print datapath
        for port_no,port in ev.msg.ports.items():
            if port.name == self.CONF.fa_br_name:
                # We found our datapath
                print "Found %s\n" % port.name
                self.switch = {'datapath': datapath}
            if port.name == self.CONF.fa_tun_name:
                # We found our fa tunnel port
                print "Found %s tunnel\n" % port.name
                self.tunnel_port = port

        if not self.switch:
            raise RyuException("No DOVE FA bridge yet")

    def _find_url(self, tenant_id, name):
        for site in tenants_site_tables[tenant_id]:
            if site['name'] == name:
                return site['fa_url']

        raise RyuException("Error finding FA url on %s" % name)

    def _send_location_req(self, tenant_id, vnid, vip, net):
        logging.debug('Send location-req %d:%d %s to %s', tenant_id, vnid, vip, net['site_name'])
        fa_url = self._find_url(tenant_id, net['site_name'])
        auth = HTTPBasicAuth('admin', 'admin')
        headers = {'content-type': 'application/json', 'Accept': 'application/json', 'charsets': 'utf-8'}

        r = requests.post('http://' + fa_url + url_tenants + '/' +
                          str(net['tenant_id']) + '/location-req',
                          headers=headers, auth=auth,
                          data=json.dumps({
                              "src_tenant_id" : tenant_id,
                              "dst_tenant_id" : net['tenant_id'],
                              "vnid" : net['vnid'],
                              "vip" : vip
                              }))

        if int(r.status_code) == 200:
            reply = r.json()
            validate(reply, location_reply_schema)

            pip = self.switch['datapath'].address[0]
            dp = self.switch['datapath']

            # send to SDN controller location update
            self.send_event('FaSdnController', EventLocUpdateReq(pip, reply['vnid'], str(reply['vip']), str(reply['vmac'])))

            # Set outgoing flow in the datapath
            dp = self.switch['datapath']
            ofproto = dp.ofproto
            tunnel_port = self.tunnel_port
            parser = dp.ofproto_parser

            actions = []
            rule = nx_match.ClsRule()

            # hardware
            rule.set_in_port(tunnel_port.port_no)
            rule.set_dl_type(0x0800)

            # ip
            rule.set_nw_dst(ipv4_text_to_int(vip))
            #rule.set_nw_proto(packet[1].proto)
            #rule.set_nw_proto(4) # "ip"

            # encap
            rule.set_tun_id(vnid) # We assume DOVE sends the source VNID in the VXLAN header for now

            # set tunnel key       SET_TUNNEL
            actions.append(dp.ofproto_parser.NXActionSetTunnel(net['vnid']))

            # set tunnel dst pIP   REG_LOAD
            actions.append(dp.ofproto_parser.NXActionRegLoad(
                0x1f,        # ofs_nbits (ofs < 6 | nbits - 1)
                0x014004,    # dst
                ipv4_text_to_int(str(reply['pip']['ip']))
                ))

            # forward              OUTPUT(PROXY)
            actions.append(dp.ofproto_parser.OFPActionOutput(ofproto.OFPP_IN_PORT))

            logging.debug('Installing outgoing flow for %d:%s=>%s', net['vnid'], vip, reply['pip']['ip'])

            dp.send_flow_mod(
                rule=rule,
                cookie=0,
                command=ofproto.OFPFC_ADD,
                idle_timeout=0,
                hard_timeout=0,
                actions=actions
                )

    @set_ev_cls(EventLocationReq)
    def loc_query_handler(self, ev):
        vnid = ev.vNID
        vip = ev.vIP

        logging.debug('Enter  loc_query_handler for %d:%s', vnid, vip)

        for tenant_id,net_table in tenants_net_tables.items():
            if vnid in net_table['table']:
                for net in net_table['table'][vnid]:
                    if net['site_name'] != self.CONF.my_site:
                        self._send_location_req(tenant_id, vnid, vip, net)
                found = True
                break

        if not found:
            raise RyuException("Can not find VNID %s" % vnid)

    @set_ev_cls(ofp_event.EventOFPVendor, MAIN_DISPATCHER)
    def nx_packet_in_handler(self, ev):
        packet = Packet(ev.msg.data.frame[2:])

        logging.info("Packet in arrived %s-->%s- no flow in datapath" % (packet[1].src, packet[1].dst))

        return
        #raise RyuException("Packet in arrived %s-->%s- no flow in datapath" % (packet[1].src, packet[1].dst))
#         in_port = ev.msg.data.match.in_port
#         if in_port < 0: return

#         packet = Packet(ev.msg.data.frame[2:])
#         if len(packet) < 1: return

#         dp = ev.msg.datapath
#         ofproto = dp.ofproto

#         vnid = ev.msg.data.match.tun_id

#         actions = []

#         rule = nx_match.ClsRule()

#         # hardware
#         rule.set_in_port(in_port)
#         rule.set_dl_type(packet[0].ethertype)

#         # ip
#         rule.set_nw_src(ipv4_text_to_int(packet[1].src))
#         rule.set_nw_dst(ipv4_text_to_int(packet[1].dst))
#         #rule.set_nw_proto(packet[1].proto)
#         rule.set_nw_proto(4) # "ip"

#         # encap
#         rule.set_tun_id(vnid)

#         # set tunnel key       SET_TUNNEL
#         actions.append(dp.ofproto_parser.NXActionSetTunnel(1234))

#         # set tunnel dst pIP   REG_LOAD
#         actions.append(dp.ofproto_parser.NXActionRegLoad(
#             0x1f,        # ofs_nbits (ofs < 6 | nbits - 1)
#             0x014004,    # dst
#             ipv4_text_to_int("1.2.3.4")
#             ))

#         # forward              OUTPUT(PROXY)
#         actions.append(dp.ofproto_parser.OFPActionOutput(ofproto.OFPP_IN_PORT))

#         logging.debug('installing proxy flow for %s:%d=>%s:%d', packet[1].src, vnid, packet[1].dst, 1234)

#         dp.send_flow_mod(
#             rule=rule,
#             cookie=0,
#             command=ofproto.OFPFC_ADD,
#             idle_timeout=60,
#             hard_timeout=600,
#             actions=actions
#             )

#         if ev.msg.data.buffer_id != ofproto_v1_0.OFPP_MAX:

#             logging.info('forcing out buffered packet')

#             out = dp.ofproto_parser.OFPPacketOut(
#                 datapath=dp, buffer_id=ev.msg.data.buffer_id,
#                 in_port=in_port, actions=actions)

#             dp.send_msg(out)

#         for item in packet:
#             if isinstance(item, str): break
#             print item

# REST API schema
tenant_schema = { "type" : "object",
                  "properties" : {
                      "id" :  {
                          "type" : "string"
                      },
                      "name" :  {
                          "type" : "string"
                      }
                  },
                  "required" : ["id", "name"]
                }

ip_addr_schema = { "type" : "object",
                   "properties" : {
                       "ip" : {
                           "type" : "string"
                           },
                       "port" : {
                           "type" : "integer"
                           }
                       },
                   "required" : ["ip"]
                   }

site_schema = { "type" : "object",
                "properties" : {
                    "name" :  {
                        "type" : "string"
                        },
                    "tenant_id" : {
                        "type" : "string"
                        },
                    "fa_url" : {
                        "type" : "string"
                        },
                    "site_proxy" : {
                        "type" : "array",
                        "items" : ip_addr_schema
                        }
                    },
                "required" : ["name", "tenant_id", "fa_url", "site_proxy"]
                }

site_table_schema = { "type" : "array",
                      "items" : site_schema
                    }

net_schema = { "type" : "object",
               "properties" : {
                   "name" : {
                       "type" : "string"
                       },
                   "tenant_id" : {
                       "type" : "string"
                       },
                   "vnid" : {
                       "type" : "string"
                       },
                   "site_name" : {
                       "type" : "string"
                       }
                   },
               "required" : ["name", "tenant_id", "vnid", "site_name"]
               }

net_table_schema = { "type" : "object",
                     "properites" : {
                         "version" : {
                             "type" : "integer"
                         },
                         "table" : {
                             "type" : "array",
                             "items" : {
                                 "type" : "array",
                                 "items" : net_schema
                                 }
                             }
                         }
                     }

handshake_schema = { "type" : "object",
                      "properties" : {
                          "version" : {
                              "type" : "integer",
                              },
                          "src_site" : {
                              "type" : "string",
                              },
                          "tenant_id" : {
                              "type" : "string",
                              },
                          "tunnel_ip" : {
                              "type" : "string",
                              },
                          "tunnel_type" : {
                              "type" : "string",
                              }
                          },
                      "required" : ["version", "src_site",
                                    "tenant_id", "tunnel_ip",
                                    "tunnel_type"]
                      }

location_request_schema = { "type" : "object",
                            "properties" : {
                                "src_tenant_id" : {
                                    "type" : "integer",
                                    },
                                "dst_tenant_id" : {
                                    "type" : "integer",
                                    },
                                "vnid" : {
                                    "type" : "integer",
                                    },
                                "vip" : {
                                    "type" : "string",
                                    }
                                },
                            "required" : ["vnid", "vip"]
                            }

location_reply_schema = { "type" : "object",
                          "properties" : {
                              "tenant_id" : {
                                  "type" : "integer",
                                  },
                              "vnid" : {
                                  "type" : "integer",
                                  },
                              "vip" : {
                                  "type" : "string",
                                  },
                              "vmac" : {
                                  "type" : "string",
                                  },
                              "pip" : ip_addr_schema
                              },
                          "required" : ["vnid", "vip", "pip"]
                          }

tenants = {}
tenants_site_tables = {}
tenants_net_tables = {}

class DoveFaApi(ControllerBase):
    VNID_REGISTER_INTERVAL = 1200

    def __init__(self, req, link, data, **config):
        super(DoveFaApi, self).__init__(req, link, data, **config)
        self.dove_switch_app = data[dove_fa_api_instance_name]
        self.my_site = self.dove_switch_app.CONF.my_site
        #hub.spawn(self._vnid_registration)

    def _vnid_registration(self):
        while True:
            print "sleep"
            hub.sleep(self.VNID_REGISTER_INTERVAL)
            for table in tenants_net_tables.values():

                self._register_networks(table)

#lookup for tenant ID translation for corresponding site
    def _site_tenant(self, site_id, tenant_id):
        if tenant_id in tenants_site_tables:
            site_table = tenants_site_tables[tenant_id]
            distant_tenant_attr = site_table[site_id]
            return distant_tenant_attr

        raise RyuException("Tenant translation failed")

#lookup for network ID translation for specific VN ID
    def _site_network(self, site_name, tenant_id, network_id):
        if tenant_id in tenants_net_tables:
            net_table = tenants_net_tables[tenant_id]
            net_list =  net_table['table'][network_id]
            for site_net_attr in net_list:
                if site_net_attr['site_name'] == site_name:
                    return site_net_attr['vnid']

        raise RyuException("Network translation failed")

#changing the keys of the net table for faster lookup
    def _process_net_table(self, net_table):
        table = { 'version' : net_table['version'], 'table' : {}}

        for net_list in net_table['table']:
            for site_net_attr in net_list:

                if site_net_attr['site_name'] == self.my_site:
                    table['table'].update({ site_net_attr['vnid'] : net_list })
                    break

        return table

    def _vnid_uuid_to_vnid(self, uuid):
        return int(hashlib.sha1(uuid).hexdigest(), 16) % (1<<23)

    def _add_flows_for_vnid(self, tenant_id, vnid, port):
        dp = self.dove_switch_app.switch['datapath']
        ofproto = dp.ofproto
        tunnel_port = self.dove_switch_app.tunnel_port
        parser = dp.ofproto_parser

        # outgoing flow
        actions = []
        rule = nx_match.ClsRule()

        # hardware
        command = ovs_vsctl.VSCtlCommand('get', ('Interface', port, 'ofport'))
        self.dove_switch_app.vsctl.run_command([command])

        assert len(command.result) == 1
        ofport = command.result[0][0]
        
        rule.set_in_port(ofport)

        for site in tenants_site_tables[tenant_id]:
            print "Set flow for ip %s\n" % site['site_proxy'][0]['ip']
            if site['name'] != self.my_site:
                print "append %s\n" % self._vnid_uuid_to_vnid(self._site_network(site['name'], tenant_id, vnid))
                # set tunnel key       SET_TUNNEL
                actions.append(dp.ofproto_parser.NXActionSetTunnel(self._vnid_uuid_to_vnid(self._site_network(site['name'], tenant_id, vnid))))
                # set tunnel dst pIP   REG_LOAD
                actions.append(dp.ofproto_parser.NXActionRegLoad(
                    0x1f,        # ofs_nbits (ofs < 6 | nbits - 1)
                    0x014004,    # dst
                    ipv4_text_to_int(str(site['site_proxy'][0]['ip']))
                    ))

                # forward              OUTPUT(PROXY)
                actions.append(dp.ofproto_parser.OFPActionOutput(tunnel_port.port_no))
                logging.debug('Installing outgoing flow for %s=>%s',
                              self._vnid_uuid_to_vnid(self._site_network(site['name'], tenant_id, vnid)),
                              site['site_proxy'][0]['ip'])

        res= dp.send_flow_mod(
            rule=rule,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            actions=actions
            )
        print "result %s\n" % res

        # ingoing flow
        actions = []
        rule = nx_match.ClsRule()

        rule.set_in_port(tunnel_port.port_no)
        rule.set_tun_id(self._vnid_uuid_to_vnid(vnid))
        
        # forward              OUTPUT(PROXY)
        actions.append(dp.ofproto_parser.OFPActionOutput(ofport))
        logging.debug('Installing incoming flow for %s=>%sofport', vnid, ofport)

        res= dp.send_flow_mod(
            rule=rule,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            actions=actions
            )
        print "result %s\n" % res

    def _register_networks(self, table, tenant_id):
        pip = self.dove_switch_app.switch['datapath'].address[0]

        for vnid in table['table']:
            print "Register %s in controller\n" % vnid
            rep = self.dove_switch_app.send_request(EventRegisterVNIDReq(vnid, pip))

            print "Got reply PPPP %s port %s\n" % (rep,rep.port)

            if rep.port:
                print "register vnid return %s\n" % rep
                self._add_flows_for_vnid(tenant_id, vnid, rep.port)
            else:
                raise RyuException("Error failed to create port for vnid %s\n" % vnid)

    def _validate_datapath(self):
        if not self.dove_switch_app.switch:
            raise RyuException("FA handshake failed: No datapath")

    def _process_handshake_req(self, site, msg):
        reply = msg.copy()
        reply['src_site'] = self.my_site
        reply['tenant_id'] = site['tenant_id']
        reply['tunnel_ip'] = self.dove_switch_app.switch['datapath'].address[0]

        if not site['handshake_state']:
            return (500, "Handshake Error")
        elif site['handshake_state'] == 'SUCCESS' or \
               site['handshake_state'] == 'PENDING':

            site['handshake_state'] = 'SUCCESS'
            site['tunnel_attr'] = {"tunnel_ip" : msg['tunnel_ip'],
                                   "tunnel_type" : msg['tunnel_type']
                                   }
            return (200, reply)
        else:
            return (500, "Unknown Error")

    def do_handshake(self, site, version):
        site['handshake_state'] = 'PENDING'
        ipaddr = \
               self.dove_switch_app.switch['datapath'].address[0]

        auth = HTTPBasicAuth('admin', 'admin')
        headers = {'content-type': 'application/json', 'Accept': 'application/json', 'charsets': 'utf-8'}

        r = requests.post('http://' + site['fa_url'] + url_tenants + '/' +
                          str(site['tenant_id']) + '/handshake',
                          headers=headers, auth=auth,
                          data=json.dumps(
                              {
                                  "version" : version,
                                  "src_site" : self.my_site,
                                  "tenant_id" : site['tenant_id'],
                                  "tunnel_ip" : ipaddr,
                                  "tunnel_type" : 'VXLAN'
                                  }
                              ))

        if int(r.status_code) == 200:
            msg = r.json()
            validate(msg, handshake_schema)

            site['handshake_state'] = 'SUCCESS'
            site['tunnel_attr'] = {"tunnel_ip" : msg['tunnel_ip'],
                                   "tunnel_type" : msg['tunnel_type']
                                   }
            return
        raise RyuException("FA handshake failed %s" % r.text)

    def sites_handshake(self, tenant_id):
        version = tenants_net_tables[tenant_id]['version']

        for site in tenants_site_tables[tenant_id]:
            if site['name'] != self.my_site:

                self.do_handshake(site, version)

    @route('dove-fa', url_tenants, methods=['GET'])
    def list_tenants(self, req, **kwargs):
        body = json.dumps(tenants)
        return Response(content_type='application/json', body=body)

    # implicitly create sites table with local site (single column)
    #  and empty network table
    @route('dove-fa', url_tenants, methods=['POST'])
    def create_tenant(self, req, **kwargs):
        tenant = json.loads(req.body)
        validate(tenant, tenant_schema)

        tenants.update({tenant['id'] : tenant})

        tenants_site_tables.update({tenant['id'] : {}})
        tenants_net_tables.update({tenant['id'] : {}})

        body = json.dumps(tenant)
        return Response(content_type='application/json', body=body)

    @route('dove-fa', url_tenants + '/{tenant_id}', methods=['GET'],
           requirements= {'tenant_id' : TENANTID_PATTERN })
    def get_tenant(self, req, tenant_id, **kwargs):

        if tenant_id in tenants:
            body = json.dumps(tenants[tenant_id])
            return Response(content_type='application/json', body=body)
        else:
            return Response(content_type='application/json', status = 500)

    @route('dove-fa', url_tenants + '/{tenant_id}', methods=['DELETE'],
           requirements= {'tenant_id' : TENANTID_PATTERN })
    def delete_tenant(self, req, tenant_id, **kwargs):

        if tenant_id in tenants:
            tenant = tenants[tenant_id]
            del tenants[tenant_id]
            del tenants_site_talbes[tenant_id]
            del tenants_net_tables[tenant_id]

            body = json.dumps(tenant)
            return Response(content_type='application/json', body=body)
        else:
            return Response(content_type='application/json', status = 500)

    @route('dove-fa', url_tenants + '/{tenant_id}/sites', methods=['PUT'],
           requirements= {'tenant_id' : TENANTID_PATTERN })
    def update_tenant_sites(self, req, tenant_id, **kwargs):
        if tenant_id in tenants_site_tables:
            site_table = tenants_site_tables[tenant_id]
        else:
            return Response(content_type='application/json',status = 500)

        table = json.loads(req.body)
        validate(table, site_table_schema)

        tenants_site_tables[tenant_id] = table

        body = json.dumps(table)
        return Response(content_type='application/json', body=body)

    @route('dove-fa', url_tenants + '/{tenant_id}/sites', methods=['DELETE'],
           requirements= {'tenant_id' : TENANTID_PATTERN })
    def delete_tenant_sites(self, req, tenant_id, **kwargs):

        if tenant_id in tenants_site_tables:
            site_table = tenants_site_tables[tenant_id]
            tenants_site_tables[tenant_id] = {}
        else:
            return Response(content_type='application/json',status = 500)

        body = json.dumps(site_table)
        return Response(content_type='application/json')

    @route('dove-fa', url_tenants + '/{tenant_id}/sites', methods=['GET'],
           requirements= {'tenant_id' : TENANTID_PATTERN })
    def get_tenant_sites(self, req, tenant_id, **kwargs):

        if tenant_id in tenants_site_tables:
            site_table = tenants_site_tables[tenant_id]
        else:
            return Response(content_type='application/json',status = 500)

        body = json.dumps(site_table)
        return Response(content_type='application/json', body=body)

    @route('dove-fa', url_tenants + '/{tenant_id}/networks_table',
           methods=['PUT'], requirements= {'tenant_id' : TENANTID_PATTERN })
    def update_net_table(self, req, tenant_id, **kwargs):

        if tenant_id in tenants_net_tables:
            net_table = tenants_net_tables[tenant_id]
        else:
            return Response(content_type='application/json',status = 500)

        table = json.loads(req.body)
        validate(table, net_table_schema)

        self._validate_datapath()

        table = self._process_net_table(table)

        tenants_net_tables[tenant_id] = table

        try:
            self.sites_handshake(tenant_id)
        except RyuException, e:
            return Response(content_type='application/json', body=str(e), status = 500)

        self._register_networks(table, tenant_id)
        
        body = json.dumps(table)
        return Response(content_type='application/json', body=body)

    @route('dove-fa', url_tenants + '/{tenant_id}/networks_table',
           methods=['GET'], requirements= {'tenant_id' : TENANTID_PATTERN })
    def get_net_table(self, req, tenant_id, **kwargs):

        if tenant_id in tenants_net_tables:
            net_table = tenants_net_tables[tenant_id]
        else:
            return Response(content_type='application/json',status = 500)

        body = json.dumps(net_table)
        return Response(content_type='application/json', body=body)

    @route('dove-fa', url_tenants + '/{tenant_id}/networks_table',
           methods=['DELETE'], requirements= {'tenant_id' : TENANTID_PATTERN })
    def delete_net_table(self, req, tenant_id, **kwargs):

        if tenant_id in tenants_net_tables:
            net_table = tenants_net_tables[tenant_id]
            tenants_net_tables[tenant_id] = {}
        else:
            return Response(content_type='application/json',status = 500)

        body = json.dumps(net_table)
        return Response(content_type='application/json', body=body)

    @route('dove-fa', url_tenants + '/{tenant_id}/handshake',
           methods=['POST'], requirements= {'tenant_id' : TENANTID_PATTERN })
    def hand_shake(self, req, tenant_id, **kwargs):

        if (tenant_id in tenants_net_tables and tenants_net_tables[tenant_id]) and (tenant_id in tenants_site_tables and tenants_site_tables[tenant_id]):
            net_table = tenants_net_tables[tenant_id]
            site_table = tenants_site_tables[tenant_id]
        else:
            return Response(content_type='application/json',status = 500, body="Handshake failed: Missing site/net table XXX Pending.")

        # Handshake validation
        msg = json.loads(req.body)
        validate(msg, handshake_schema)

        if msg['version'] != net_table['version']:
            raise RyuException("Handshake failed: Version mismatch %s %s" %
                               (msg['version'], net_table['version']))

        print "DO HANDSHAKE"

        for site in tenants_site_tables[tenant_id]:
            if site['name'] == msg['src_site']:

                status, body = self._process_handshake_req(site, msg)

                body = json.dumps(body)
                return Response(content_type='application/json', body=body)

        return Response(content_type='application/json',status = 500, body="Handshake failed: Src site was not found.")

    @route('dove-fa', url_tenants + '/{tenant_id}/location-req',
           methods=['POST'], requirements= {'tenant_id' : TENANTID_PATTERN })
    def location_request(self, req, tenant_id, **kwargs):

        msg = json.loads(req.body)
        validate(msg, location_request_schema)

        logging.debug('Enter location_request with %s', msg)

        # send location request to controller
        reply = self.dove_switch_app.send_request(EventLocationReq(msg['vnid'], str(msg['vip'])))

        # XXX return error code
        if reply.vIP == "0.0.0.0":
            return Response(content_type='application/json', status = 500)

        # set incoming flow in the datapath
        dp = self.dove_switch_app.switch['datapath']
        tunnel_port = self.dove_switch_app.tunnel_port

        rule = nx_match.ClsRule()
        actions = []
        ofproto = dp.ofproto

        # hardware
        rule.set_in_port(tunnel_port.port_no)
        rule.set_dl_type(0x0800)

        # ip
        rule.set_nw_dst(ipv4_text_to_int(str(msg['vip'])))
        #rule.set_nw_proto(packet[1].proto)
        #rule.set_nw_proto(4) # "ip"

        # encap
        rule.set_tun_id(msg['vnid'])

        # set tunnel key       SET_TUNNEL
        actions.append(dp.ofproto_parser.NXActionSetTunnel(msg['vnid']))

        # set tunnel dst pIP   REG_LOAD
        actions.append(dp.ofproto_parser.NXActionRegLoad(
            0x1f,        # ofs_nbits (ofs < 6 | nbits - 1)
            0x014004,    # dst
            ipv4_text_to_int(reply.pIP)
            ))

        # forward              OUTPUT(PROXY)
        actions.append(dp.ofproto_parser.OFPActionOutput(ofproto.OFPP_IN_PORT))

        logging.debug('Installing incoming flow for %d:%s=>%s', msg['vnid'], msg['vip'], reply.pIP)

        dp.send_flow_mod(
            rule=rule,
            cookie=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0,
            actions=actions
            )

        # Send reply to peer FA
        net_list = tenants_net_tables[tenant_id]['table'][msg['vnid']]

        vnid = ""
        for net in net_list:
            if net['tenant_id'] == msg['src_tenant_id']:
                vnid = net['vnid']

        if not vnid:
            raise RyuException("Can not find peer network")

        body = { "vnid" : vnid,
                 "vip" : msg['vip'],
                 "vmac" : reply.vMAC,
                 "tenant_id" : msg['src_tenant_id'],
                 "pip" : { "ip" : self.dove_switch_app.switch['datapath'].address[0] }
                 }

        body = json.dumps(body)
        return Response(content_type='application/json', body=body)
