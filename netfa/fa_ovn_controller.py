from netfa.fa_sdn_controller import FaSdnController
from netfa.fa_sdn_controller import RegisterVNIDReq
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

class OvnController(FaSdnController):
    def initialize(self):
        return

    def __init__(self):
        super(OvnController, self).__init__()

    def test(self):
        print "test\n"

    @set_ev_cls(RegisterVNIDReq, MAIN_DISPATCHER)
    def register_vnid_handler(self, req):
        print "test2\n"
