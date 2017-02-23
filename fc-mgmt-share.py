###########################################################################
#Copyright 2016 Anna Levin, Liran Shour - IBM
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
from neutronclient.neutron import client as nclient
from keystoneauth1.identity import v2
from keystoneauth1 import session
from keystoneclient.v2_0 import client as kclient
from requests.auth import HTTPBasicAuth
from oslo.config import cfg
import requests
import json
import time

opt_group = cfg.OptGroup(name='mgmt',
                         title='A shim fa mgmt layer')

fa_opts = [
    cfg.StrOpt('username', default='admin'),
    cfg.StrOpt('password', default='password'),
    cfg.StrOpt('tenant_name', default=None),
    cfg.StrOpt('site1_ip', default=None),
    cfg.StrOpt('site2_ip', default=None),
    cfg.StrOpt('site1_name', default='site1'),
    cfg.StrOpt('site2_name', default='site2'),
    cfg.StrOpt('fa1_ip', default=None),
    cfg.StrOpt('fa2_ip', default=None),
    cfg.IntOpt('fa1_port', default=4789),
    cfg.IntOpt('fa2_port', default=4789),
    cfg.StrOpt('fa1_dp_ip', default=None),
    cfg.StrOpt('fa2_dp_ip', default=None),
    cfg.IntOpt('fa1_dp_port', default=4789),
    cfg.IntOpt('fa2_dp_port', default=4789)
]

CONF = cfg.CONF
CONF.register_group(opt_group)
CONF.register_opts(fa_opts, 'mgmt')

CONF(default_config_files=['netfa.conf'])

username=CONF.mgmt.username
password=CONF.mgmt.password
tenant_name=CONF.mgmt.tenant_name
site1=CONF.mgmt.site1_ip
site2=CONF.mgmt.site2_ip

auth_url1='http://' + CONF.mgmt.site1_ip + ':5000/v2.0'
auth_url2='http://' + CONF.mgmt.site2_ip + ':5000/v2.0'
fa_url1=CONF.mgmt.fa1_ip + ':' + str(CONF.mgmt.fa1_port)
fa_url2=CONF.mgmt.fa2_ip + ':' + str(CONF.mgmt.fa2_port)

print "Setup federation between %s to %s for tenant %s\n" % (CONF.mgmt.site1_name, CONF.mgmt.site2_name, tenant_name)

def get_tenant(auth_url):
    auth = v2.Password(username=username, password=password, tenant_name=tenant_name, auth_url=auth_url)    
    sess = session.Session(auth=auth)
    keystone = kclient.Client(session=sess)
    tenants = keystone.tenants.list()

    t=None
    for t in tenants:
        if t.name == tenant_name:
            break

    if t:
        return {"name" : t.name, "id": t.id}
    return None

tenant1 = get_tenant(auth_url1)
tenant2 = get_tenant(auth_url2)

print "Create tenants on network federation agents..."
print "tenant1 = %s\ntenant2 = %s\n" % (tenant1, tenant2)
auth = HTTPBasicAuth(username, password)
headers = {'content-type': 'application/json', 'Accept': 'application/json', 'charsets': 'utf-8'}

r = requests.post('http://' + fa_url1 + '/net-fa/tenants', headers=headers, auth=auth, data=json.dumps(tenant1))
r = requests.post('http://' + fa_url2 + '/net-fa/tenants', headers=headers, auth=auth, data=json.dumps(tenant2))

print "Create tenant sites table\n"
sites = []
site = { 'name' : CONF.mgmt.site1_name,
         'tenant_id' : tenant1['id'],
         'fa_url' : fa_url1,
         'site_proxy' : [{'ip' : CONF.mgmt.fa1_dp_ip, 'port' : CONF.mgmt.fa1_dp_port}]
         }
sites.append(site)
site = { 'name' : CONF.mgmt.site2_name,
         'tenant_id' : tenant2['id'],
         'fa_url' : fa_url2,
         'site_proxy' : [{'ip' : CONF.mgmt.fa2_dp_ip, 'port' : CONF.mgmt.fa2_dp_port}]
         }
sites.append(site)
print "Update tenant's site table %s\n" % sites
r = requests.put('http://' + fa_url1 + '/net-fa/tenants/' + tenant1['id'] + '/sites', headers=headers, auth=auth, data=json.dumps(sites))
print "Created sites table on site1: %s\n" % r.text
r = requests.put('http://' + fa_url2 + '/net-fa/tenants/' + tenant2['id'] + '/sites', headers=headers, auth=auth, data=json.dumps(sites))
print "Created sites table on site2: %s\n" % r.text

print 'Create network table id are strings\n'
net_table=[]
neutron1 = nclient.Client('2.0', auth_url=auth_url1, username=username, password=password, tenant_name=tenant_name)
neutron1.format = 'json'
networks1 = neutron1.list_networks()

neutron2 = nclient.Client('2.0', auth_url=auth_url2, username=username, password=password, tenant_name=tenant_name)
neutron2.format = 'json'
networks2 = neutron2.list_networks()
for n1 in networks1['networks']:
    net =[]
    for n2 in networks2['networks']:
        if n1['name'] == n2['name']:
            print 'we have a match %s\n' % n1
            net.append({ 'name' : n1['name'],
                         'vnid' : n1['id'],
                         'site_name' : CONF.mgmt.site1_name,
                         'tenant_id' : tenant1['id']
                         }
                       )
            net.append({ 'name' : n2['name'],
                         'vnid' : n2['id'],
                         'site_name' : CONF.mgmt.site2_name,
                         'tenant_id' : tenant2['id']
                         }
                       )
            break
    if net:
        net_table.append(net)

print "Update net table on sites:\n %s" % net_table
r = requests.put('http://' + fa_url1 + '/net-fa/tenants/' + tenant1['id'] + '/networks_table', headers=headers, auth=auth, data=json.dumps({'version' : 111, 'table' : net_table} ))

print "Update net table returned %s %s\n" %(r.status_code, r.text)
time.sleep(1)

r = requests.put('http://' + fa_url2 + '/net-fa/tenants/' + tenant2['id'] + '/networks_table', headers=headers, auth=auth, data=json.dumps({'version' : 111, 'table' : net_table}))

r = requests.get('http://' + fa_url2 + '/net-fa/tenants/' + tenant2['id'] + '/networks_table')

print "Configured net table:\n %s" % r.text
