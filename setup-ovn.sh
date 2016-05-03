#!/bin/bash
OVS_DIR=/home/ubuntu/ovs
HOST_IP=$1
OVN_DB_IP=$2
echo "host ip = $HOST_IP ovn db ip = $OVN_DB_IP"

# || [ -z "$OVN_DB_IP" ||]]; then
if [ -z "$HOST_IP" ] || [ -z $OVN_DB_IP ] ; then
    echo "Usage: setup-ovn.sh <host_ip> <ovn_db_ip>"
    exit
fi

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
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-remote="tcp:$OVN_DB_IP:6642"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-bridge="br-int"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-encap-type="geneve"
sudo ovs-vsctl --no-wait set open_vswitch . external-ids:ovn-encap-ip="$HOST_IP"

sudo ovs-vsctl --no-wait -- --may-exist add-br br-int
sudo ovs-vsctl --no-wait br-set-external-id br-int bridge-id br-int
sudo ovs-vsctl --no-wait set bridge br-int fail-mode=secure other-config:disable-in-band=true

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
