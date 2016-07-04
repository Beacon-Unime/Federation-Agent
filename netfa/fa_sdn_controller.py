###########################################################################
#Copyright [2016] [Anna Levin, Lyran Shour - IBM]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
############################################################################



from abc import ABCMeta, abstractmethod
import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu import cfg
from ryu.controller.event import EventRequestBase, EventReplyBase

controllerName = None

class EventRegisterVNIDReq(EventRequestBase):
    def __init__(self, vNID, pIP):
        super(EventRegisterVNIDReq, self).__init__()
        self.dst = controllerName
        self.vNID = vNID
        self.pIP = pIP

class EventRegisterVNIDReply(EventReplyBase):
    def __init__(self, dst, vNID, pIP, port):
        super(EventRegisterVNIDReply, self).__init__(dst)
        self.dst = dst
        self.vNID = vNID
        self.pIP = pIP
        self.port = port

class EventUpdateHostedMacs(EventRequestBase):
    def __init__(self, vNID, vMAC_list):
        self.vNID = vNID
        self.vIP = vIP
        self.vMAC_list = vMAC_list

class EventUpdateLocalHostedMacs(EventUpdateHostedMacs):
    def __init__(self, vNID, vMAC_list):
        super(EventUpdateHostedMacs, self).__init__(vNID, vMAC_list)

class EventUpdateRemoteHostedMacs(EventUpdateHostedMacs):
    def __init__(self, vNID, vMAC_list):
        super(EventUpdateHostedMacs, self).__init__(vNID, vMAC_list)

_app = None

class FaSdnController(app_manager.RyuApp):
    _EVENTS=[EventRegisterVNIDReq]

    def __init__(self, *args, **kwargs):
        global _app
        assert _app is None

        _app = self
        super(FaSdnController, self).__init__(*args, **kwargs)
        global controllerName
        controllerName = self.get_module_name()
        self.CONF.register_opts([
            cfg.StrOpt('fa_br_name', default=None),
            cfg.StrOpt('controller_br_name', default=None)
            ], 'netfa')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        for port_no,port in ev.msg.ports.items():
            if port.name == self.CONF.netfa.fa_br_name:
                # We found our datapath

                self.tunnel_port = port
                self.fa_switch = {'datapath': datapath}
                break

    @set_ev_cls(EventRegisterVNIDReq)
    def register_vnid_handler(self, req):
        port = self.register_vnid(req)

        self.reply_to_request(req, EventRegisterVNIDReply(req.src, req.vNID, req.pIP, port))

    """ API to communicate with the specific network controller """

    """ (Mandatory) Returns the class name """
    @abstractmethod
    def get_module_name():
        pass

    """ (Mandatory) Controler specific virtual network registration.
    After this call it is assumed that vnid is L2 bridged to the FA bridge.
    return: name of created VNID port on FA bridge """
    @abstractmethod
    def register_vnid(self, EventRegisterVNIDReq):
        pass

    """ (Optional) update remote hosted macs peered by FA """
    @abstractmethod
    def update_hosted_macs_by_peers(self, EventUpdateRemoteHostedMacs):
        pass
    """ (Optional) update local hosted macs """
    @abstractmethod
    def update_hosted_macs_by_local(self, EventUpdateLocalHostedMacs):
        pass
