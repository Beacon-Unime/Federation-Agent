#!/bin/bash
OVS_DIR=/home/stack/ovs
HOST_IP=$1
OVN_DB_IP=$2
echo "host ip = $HOST_IP ovn db ip = $OVN_DB_IP"

# || [ -z "$OVN_DB_IP" ||]]; then
if [ -z "$HOST_IP" ] || [ -z $OVN_DB_IP ] ; then
    echo "Usage: setup-ovs.sh <host_ip> <ovn_db_ip>"
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

echo "Configuring OVN"

if [ -z "$OVN_UUID" ] ; then
    if [ -f ./ovn-uuid ] ; then
        OVN_UUID=$(cat ovn-uuid)
    else
        OVN_UUID=$(uuidgen)
        echo $OVN_UUID > ovn-uuid
    fi
fi
echo $OVN_UUID > ovn-uuid

sudo ovs-vsctl --no-wait set open_vswitch . external-ids:system-id="$OVN_UUID"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-remote="tcp:$OVN_DB_IP:6640"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-bridge="br-int"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-encap-type="geneve"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-encap-ip="$HOST_IP"

sudo ovs-vsctl --no-wait -- --may-exist add-br br-int
sudo ovs-vsctl --no-wait br-set-external-id br-int bridge-id br-int
sudo ovs-vsctl --no-wait set bridge br-int fail-mode=secure other-config:disable-in-band=true

echo "Start ovs deamon"
sudo ovs-vswitchd --pidfile --detach --log-file

sudo ovs-vsctl add-br br-fa
sudo ovs-vsctl -- --may-exist add-port br-fa fa-tun -- set Interface fa-tun type=vxlan options:remote_ip=flow options:key=flow
sudo ovs-vsctl set-controller br-fa tcp:127.0.0.1:1234

echo "Start OVN..."

sudo screen -S ovn -p 0 -X kill
sudo screen -S ovn -p 1 -X kill
sudo screen -S ovn -p 2 -X kill

sudo screen -d -m -S ovn
sudo screen -S ovn -X screen -t ovn-controller
sleep 1
sudo screen -t ovn screen -S ovn -p 0 -X stuff "sudo ovn-controller --log-file unix:/usr/local/var/run/openvswitch/db.sock `echo -ne '\015'`"
sudo screen -S ovn -X screen -t ovn-northd
sleep 1
sudo screen -t ovn screen -S ovn -p 1 -X stuff "sudo ovn-northd --log-file `echo -ne '\015'`"
