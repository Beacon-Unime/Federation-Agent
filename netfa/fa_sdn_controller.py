from abc import ABCMeta, abstractmethod
from ryu.controller.event import EventRequestBase, EventReplyBase

class FaSdnController(object):
    """ API to communicate with the specific cloud controller """

    __metaclass__ = ABCMeta

    @abstractmethod
    def initialize(self):
        pass

    def __init__(self):
        pass

class PolicyReq(EventRequestBase):
    def __init__(self, vNID, vIP):
        self.dst = 'FaSdnController'
        self.vNID = vNID
        self.vIP = vIP

class RegisterVNIDReq(EventRequestBase):
    def __init__(self, vNID, pIP):
        self.vNID = vNID
        self.pIP = pIP


class LocUpdateReq(EventRequestBase):
    def __init__(self, pIP, vNID, vIP, vMAC):
        self.vNID = vNID
        self.vIP = vIP
        self.pIP = pIP
        self.vMAC = vMAC

class LocationReq(EventRequestBase):
    def __init__(self, vNID, vIP):
        self.dst = 'FaSdnController'
        self.vNID = vNID
        self.vIP = vIP
