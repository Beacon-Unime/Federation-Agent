from abc import ABCMeta, abstractmethod
from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.controller.event import EventRequestBase, EventReplyBase

class EventPolicyReq(EventRequestBase):
    def __init__(self, vNID, vIP):
        self.dst = 'FaSdnController'
        self.vNID = vNID
        self.vIP = vIP

class EventRegisterVNIDReq(EventRequestBase):
    def __init__(self, vNID, pIP):
        super(EventRegisterVNIDReq, self).__init__()
        self.vNID = vNID
        self.pIP = pIP


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
        self.name = 'FaSdnController'
        _app = self
        print "INIT"
        super(FaSdnController, self).__init__(*args, **kwargs)

    @set_ev_cls(EventRegisterVNIDReq)
    def register_vnid_handler(self, req):
        print "Register vnid %s\n" % req.vNID
        self.register_vnid(req)

    """ API to communicate with the specific cloud controller """
    @abstractmethod
    def regiter_vnid(self, EventRegisterVNIDReq):
        pass
