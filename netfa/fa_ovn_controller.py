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



import uuid
import os
import logging
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
            cfg.StrOpt('ovsdb_connection', default=None)], 'ovn')

    def get_module_name(self):
        return 'OvnController'

    def register_vnid(self, req):

        # add patch port on OVN bridge
        vnid_ctl_port = self._add_patch_port(self.CONF.netfa.controller_br_name, req.vNID, 'fa-br')

        vnid_ctl_port_uuid = uuid.uuid4()

        # add port to ovnnb
        os.system('ovn-nbctl --db %s lport-add neutron-%s %s' %
                  (self.CONF.ovn.ovsdb_connection, req.vNID, vnid_ctl_port_uuid))
        os.system('ovn-nbctl --db %s lport-set-addresses %s unknown' %
                  (self.CONF.ovn.ovsdb_connection, vnid_ctl_port_uuid))
        logging.info('OVN -- Added logical port %s to switch neutron-%s\n',
                     vnid_ctl_port_uuid, req.vNID)
        
        # set external_ids
        external_ids = 'iface-id=%s, iface-status=active' % vnid_ctl_port_uuid
        command = ovs_vsctl.VSCtlCommand('set', ('Interface', vnid_ctl_port, 'type=patch',  'external_ids=%s' % external_ids))
        self.vsctl.run_command([command])

        vnid_fa_port = self._add_patch_port(self.CONF.netfa.fa_br_name, 'fa-br', req.vNID)

        logging.info('Created FA<-->OVN peer ports %s<-->%s',
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
