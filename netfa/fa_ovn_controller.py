from netfa.fa_sdn_controller import FaSdnController
from netfa.fa_sdn_controller import EventRegisterVNIDReq
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.lib.ovs.vsctl as ovs_vsctl

class OvnController(FaSdnController):
    def initialize(self):
        return

    def __init__(self, *args, **kwargs):
        super(OvnController, self).__init__(*args, **kwargs)
        self.vsctl = ovs_vsctl.VSCtl('unix:/usr/local/var/run/openvswitch/db.sock')

    def get_module_name(self):
        return 'OvnController'

    def register_vnid(self, req):

        self._add_patch_port(self.CONF.controller_br_name, req.vNID, 'fa-br')
        self._add_patch_port(self.CONF.fa_br_name, 'fa-br', req.vNID)

    def _add_patch_port(self, bridge, base, peer):
        port_name = base + "-" + peer
        peer_name = peer + "-" + base

        print "adding VNID patch port %s on bridge %s" % (port_name, bridge)

        command1 = ovs_vsctl.VSCtlCommand('add-port', (bridge, port_name), options=['--may_exist'])
        options = 'peer=%ss' % peer_name
        command2 = ovs_vsctl.VSCtlCommand('set', ('Interface', port_name, 'type=patch',  'options=%s' % options))

        self.vsctl.run_command([command1, command2])
