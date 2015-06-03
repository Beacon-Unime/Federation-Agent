What's Net-fa
=============
Net-fa is a Ryu based application that implements federation agent OF
controller.

Net-fa is a generic SDN federation agent that exposes REST API for management
and control with the Cloud Management Software and the peer federation agents.
In order to support a specific SDN implementation, one should write its own 
FaController class that is derived from the abstract FaSdnController class.

Net-fa comes with a specific reference SDN implementation for OVN in 
fa_ovn_controller.py.
If you want to Net-fa to work with ypur own SDN implementation, take a look
in FaOvnController as a reference implementation and write a class that is
dereived from the abstract class FaSdnController.

Quick Start
===========
% git clone <net-fa Git repository>
% cd net-fa; python ./setup.py install
% sudo ryu-manager --verbose --wsapi-port=4567 --ofp-tcp-listen-port=1234 --config-file=./netfa.conf ./netfa/dove_fa.py <file contains a class derived from FaSdnController e.g ./netfa/fa_ovn_controller.py>

Ryu-manager runs 2 Ryu applications dove_fa.py that implements all the rest 
APIs and controlling the FA datapath and a class that implements 
FaSdnController (e.g FaOvnController)
