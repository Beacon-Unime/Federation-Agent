import uuid
import os
import logging
from netfa.fa_sdn_controller import FaSdnController
from netfa.fa_sdn_controller import EventRegisterVNIDReq
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.lib.ovs.vsctl as ovs_vsctl
from ryu import cfg

class FaBridge(FaSdnController):
    def initialize(self):
        return

    def __init__(self, *args, **kwargs):
        super(FaBridge, self).__init__(*args, **kwargs)
        self.vsctl = ovs_vsctl.VSCtl('unix:/usr/local/var/run/openvswitch/db.sock')

    def get_module_name(self):
        return 'FaBridge'

    def register_vnid(self, req):

        # add patch port on OVN bridge
        vnid_ctl_port = self._add_patch_port(self.CONF.netfa.controller_br_name, req.vNID, 'fa-br')

        vnid_fa_port = self._add_patch_port(self.CONF.netfa.fa_br_name, 'fa-br', req.vNID)

        logging.info('Created FA<-->Bridge peer ports %s<-->%s',
                     vnid_ctl_port, vnid_fa_port)

        return vnid_fa_port

    def _add_patch_port(self, bridge, base, peer):
        port_name = base + "-" + peer
        peer_name = peer + "-" + base

        command1 = ovs_vsctl.VSCtlCommand('add-port', (bridge, port_name), options=['--may_exist'])
        options = 'peer=%s' % peer_name
        command2 = ovs_vsctl.VSCtlCommand('set', ('Interface', port_name, 'type=patch',  'options=%s' % options))

        self.vsctl.run_command([command1, command2])

        return port_name
