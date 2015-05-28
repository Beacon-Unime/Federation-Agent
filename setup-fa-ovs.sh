#!/bin/bash
OVS_DIR=/home/stack/ovs
HOST_IP=$1

echo "host ip = $HOST_IP"

# || [ -z "$OVN_DB_IP" ||]]; then
if [ -z "$HOST_IP" ]; then
    echo "Usage: setup-ovs.sh <host_ip>"
    exit
fi

sudo killall ovsdb-server
sudo ovs-appctl exit

sudo rm -rf /usr/local/etc/openvswitch/conf.db

sudo mkdir -p /usr/local/etc/openvswitch
sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db $OVS_DIR/vswitchd/vswitch.ovsschema


echo "run ovsdb-server"
sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                     --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                     --pidfile --detach

echo -n "Waiting for ovsdb-server to start ... "
    while ! test -e /usr/local/var/run/openvswitch/db.sock ; do
        sleep 1
    done
echo "done."

sudo ovs-vsctl --no-wait init

sudo modprobe openvswitch || die $LINENO "Failed to load openvswitch module"
sudo modprobe geneve || true
sudo modprobe vport_geneve || die $LINENO "Failed to load vport_geneve module"

echo "kernel module loaded"

echo "Start ovs deamon"
sudo ovs-vswitchd --pidfile --detach --log-file

sudo ovs-vsctl add-br br-fa
sudo ovs-vsctl -- --may-exist add-port br-fa fa-tun -- set Interface fa-tun type=vxlan options:remote_ip=flow options:key=flow
sudo ovs-vsctl set-controller br-fa tcp:127.0.0.1:1234
