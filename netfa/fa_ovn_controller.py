import uuid
import os
from netfa.fa_sdn_controller import FaSdnController
from netfa.fa_sdn_controller import EventRegisterVNIDReq
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.lib.ovs.vsctl as ovs_vsctl
from ryu import cfg

class OvnController(FaSdnController):
    def initialize(self):
        return

    def __init__(self, *args, **kwargs):
        super(OvnController, self).__init__(*args, **kwargs)
        self.vsctl = ovs_vsctl.VSCtl('unix:/usr/local/var/run/openvswitch/db.sock')
        self.CONF.register_opts([
            cfg.StrOpt('ovsdb_connection', default=None)], 'netfa')

    def get_module_name(self):
        return 'OvnController'

    def register_vnid(self, req):

        # add patch port on OVN bridge
        port_name = self._add_patch_port(self.CONF.netfa.controller_br_name, req.vNID, 'fa-br')

        port_uuid = uuid.uuid4()

        # add port to ovnnb
        os.system('ovn-nbctl -d %s lport-add neutron-%s %s' %
                  (self.CONF.netfa.ovsdb_connection, req.vNID, port_uuid))
        os.system('ovn-nbctl -d %s lport-set-macs %s unknown' %
                  (self.CONF.netfa.ovsdb_connection, port_uuid))
        print "Added lport %s to switch neutron-%s\n" % (port_uuid, req.vNID)
        
        # set external_ids
        external_ids = 'iface-id=%s, iface-status=active' % port_uuid
        command = ovs_vsctl.VSCtlCommand('set', ('Interface', port_name, 'type=patch',  'external_ids=%s' % external_ids))
        self.vsctl.run_command([command])

        port = self._add_patch_port(self.CONF.netfa.fa_br_name, 'fa-br', req.vNID)

        return port

    def _add_patch_port(self, bridge, base, peer):
        port_name = base + "-" + peer
        peer_name = peer + "-" + base

        print "adding VNID patch port %s on bridge %s" % (port_name, bridge)

        command1 = ovs_vsctl.VSCtlCommand('add-port', (bridge, port_name), options=['--may_exist'])
        options = 'peer=%s' % peer_name
        command2 = ovs_vsctl.VSCtlCommand('set', ('Interface', port_name, 'type=patch',  'options=%s' % options))

        self.vsctl.run_command([command1, command2])

        return port_name
