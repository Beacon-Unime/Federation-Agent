#!/bin/bash
OVS_DIR=/home/stack/ovs

sudo modprobe openvswitch

sudo mkdir -p /usr/local/etc/openvswitch
sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db $OVS_DIR/vswitchd/vswitch.ovsschema

sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                     --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                     --private-key=db:Open_vSwitch,SSL,private_key \
                     --certificate=db:Open_vSwitch,SSL,certificate \
                     --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                     --pidfile --detach

sudo ovs-vsctl --no-wait init

sudo ovs-vswitchd --pidfile --detach

sudo ovs-vsctl add-br br-fa
sudo ovs-vsctl -- --may-exist add-port br-fa fa-tun -- set Interface fa-tun type=vxlan options:remote_ip=flow options:key=flow

sudo ovs-vsctl set-controller br-fa tcp:127.0.0.1:1234
