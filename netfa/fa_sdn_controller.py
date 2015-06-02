from abc import ABCMeta, abstractmethod
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu import cfg
from ryu.controller.event import EventRequestBase, EventReplyBase

controllerName = None

class EventPolicyReq(EventRequestBase):
    def __init__(self, vNID, vIP):
        self.dst = 'FaSdnController'
        self.vNID = vNID
        self.vIP = vIP

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

class EventLocUpdateReq(EventRequestBase):
    def __init__(self, pIP, vNID, vIP, vMAC):
        self.vNID = vNID
        self.vIP = vIP
        self.pIP = pIP
        self.vMAC = vMAC

class EventLocationReq(EventRequestBase):
    def __init__(self, vNID, vIP):
        self.dst = 'FaSdnController'
        self.vNID = vNID
        self.vIP = vIP

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
        print ev.msg
        print datapath
        for port_no,port in ev.msg.ports.items():
            if port.name == self.CONF.netfa.fa_br_name:
                # We found our datapath
                print "Found in controller fa bridge %s\n" % port.name
                self.tunnel_port = port
                self.fa_switch = {'datapath': datapath}
                break

    @set_ev_cls(EventRegisterVNIDReq)
    def register_vnid_handler(self, req):
        print "Register vnid %s\n" % req.vNID
        port = self.register_vnid(req)
        print "send reply with %s\n" % port
        
        self.reply_to_request(req, EventRegisterVNIDReply(req.src, req.vNID, req.pIP, port))

    """ API to communicate with the specific cloud controller """

    """ Returns the class name """
    @abstractmethod
    def get_module_name():
        pass

    """ Controler specific virtual network registration returns name of created VNID port on FA bridge"""
    @abstractmethod
    def register_vnid(self, EventRegisterVNIDReq):
        pass
