import logging
from neutronclient.neutron import client as nclient
from keystoneclient.v2_0 import client as kclient
from requests.auth import HTTPBasicAuth
import requests
import json

username='admin'
password='password'
tenant_name='demo'
site1='10.0.2.4'
site2='10.0.2.6'
auth_url1='http://' + site1 + ':5000/v2.0'
auth_url2='http://' + site2 + ':5000/v2.0'
fa_url1='10.0.2.8:4567'
fa_url2='10.0.2.6:4567'

logging.basicConfig(level=logging.INFO)

def get_tenant(auth_url):
    keystone = kclient.Client(username=username, password=password, tenant_name=tenant_name, auth_url=auth_url)
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

r = requests.post('http://' + fa_url1 + '/dove-fa/tenants', headers=headers, auth=auth, data=json.dumps(tenant1))
#r = requests.post('http://' + site2 + ':4567/dove-fa/tenants', headers=headers, auth=auth, data=json.dumps(tenant2))

print "Create tenant sites table\n"
sites = []
site = { 'name' : 'site1',
         'tenant_id' : tenant1['id'],
         'fa_url' : fa_url1,
         'site_proxy' : [{'ip' : '10.0.2.4', 'port' : 1234}]
         }
sites.append(site)
site = { 'name' : 'site2',
         'tenant_id' : tenant1['id'],
         'fa_url' : fa_url2,
         'site_proxy' : [{'ip' : '10.0.2.6', 'port' : 1234}]
         }
sites.append(site)
print "Update tenant's site table %s\n" % sites
r = requests.put('http://' + fa_url1 + '/dove-fa/tenants/' + tenant1['id'] + '/sites', headers=headers, auth=auth, data=json.dumps(sites))
#r = requests.put('http://' + site2 + ':4567/dove-fa/tenants/' + tenant2['id'] + '/sites', headers=headers, auth=auth, data=json.dumps(sites))

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
                         'site_name' : site1,
                         'tenant_id' : tenant1['id']
                         }
                       )
            net.append({ 'name' : n2['name'],
                         'vnid' : n2['id'],
                         'site_name' : site2,
                         'tenant_id' : tenant2['id']
                         }
                       )
            break
    if net:
        net_table.append(net)

print "Update net table on sites \n"
r = requests.put('http://' + fa_url1 + '/dove-fa/tenants/' + tenant1['id'] + '/networks_table', headers=headers, auth=auth, data=json.dumps({'version' : 111, 'table' : net_table} ))
#r = requests.put('http://' + site2 + ':4567/dove-fa/tenants/' + tenant2['id'] + '/network_table', headers=headers, auth=auth, data=json.dumps(net_table))
