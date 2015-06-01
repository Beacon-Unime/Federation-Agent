from netfa.fa_sdn_controller import FaSdnController
from netfa.fa_sdn_controller import EventRegisterVNIDReq
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

class OvnController(FaSdnController):
    def initialize(self):
        return

    def __init__(self, *args, **kwargs):
        super(OvnController, self).__init__(*args, **kwargs)

    def get_module_name(self):
        return 'OvnController'

    def register_vnid(self, req):
        print "test2 %s\n" % req
