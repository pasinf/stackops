#!/usr/bin/python
'''
System automation tool for creating and managing server instances in the ECE cloud environment through CLI.

Capabilities -
    * Create several virtual servers in NETO Elastic Compute Environment (ECE)
    * Operations tool for managing instances in the NETO ECE cloud
    * Provide configuration templates for managing virtual servers in the cloud
    * Automate software load balancing using HA Proxy


Author : Prashanth Hari
Email  : prashanth_hari@cable.comcast.com

Usage:
~
./stack_ops.py -h

  -h, --help            show this help message and exit
  -u USER, --user USER  Tenant username for authentication
  -p PASSWORD, --password PASSWORD
                        Tenant password
  -e ENDPOINT, --endpoint ENDPOINT
                        Endpoint Server Name
  -t TENANT, --tenant TENANT
                        Tenant/Project name
  -c NUMBER_OF_VMS, --number_of_vms NUMBER_OF_VMS
                        Number of VMs
  -s SERVER_PREFIX, --server_prefix SERVER_PREFIX
                        Server Prefix for new server creation
  -i server1:old_ip:new_ip server2:old_ip:new_ip [server1:old_ip:new_ip server2:old_ip:new_ip ...], --reassign_ip server1:old_ip:new_ip server2:old_ip:new_ip [server1:old_ip:new_ip server2:old_ip:new_ip ...]
                        Reassign Floating IP
  -d server1 server2.. [server1 server2.. ...], --delete_vms server1 server2.. [server1 server2.. ...]
                        Delete/Terminate VMs
  -H haproxy_1 haproxy_2.. [haproxy_1 haproxy_2.. ...], --haproxy haproxy_1 haproxy_2.. [haproxy_1 haproxy_2.. ...]
                        haproxy endpoints
  -l server1 server2.. [server1 server2.. ...], --add_to_lb server1 server2.. [server1 server2.. ...]
                        Add VM to loadbalancer
  -r server1 server2.. [server1 server2.. ...], --remove_from_lb server1 server2.. [server1 server2.. ...]
                        Remove VM from loadbalancer
  -m server1 server2.. [server1 server2.. ...], --maint server1 server2.. [server1 server2.. ...]
                        Set server maintenance in load balancer
  -a server1 server2.. [server1 server2.. ...], --activate server1 server2.. [server1 server2.. ...]
                        Undo server maint in loadbalancer


Revision History
~~~~~~~~~
Initial Release Date:03-04-2013


'''

import httplib
import json
from urlparse import urlparse
import urllib
from novaclient.v1_1 import client
import time
import ConfigParser
import yaml
import os
import sys
import optparse
import getpass
import ast
import argparse
import urllib2
import base64



AUTH_URL = ''
no_of_instances = 0
endpoint_urls = {}
base_image = {}
base_image_flavor = {}
USER = ''
PASS = ''
FLAVOR = 1





'''Read Configs'''
def readConfigs():
    config = ConfigParser.SafeConfigParser()
    config_file = "/home/prash/deploy/stack.yaml"

    if ( os.path.isfile(config_file) ):
        f = open(config_file)
        configdata = yaml.safe_load(f)
        f.close()
        return configdata
    else:
        print "Config file stack.yaml not found, Exiting"
        sys.exit(1)

    

'''Command Line Options'''
def setCommandOptions():
    usage='''\n
stack_ops.py -u USER -p PASSWORD -e ENDPOINT -t TENANT [-q] \n
    [ [-s] SERVER_PREFIX [-c] NUMBER_OF_VMS ] [ [-H] HAPROXY_1 HAPROXY_2 ] \n
    [ [-d] SERVER1 SERVER2.. ] [ [-H] HAPROXY_1 HAPROXY_2 ] \n
    [ [-i] SERVER_1:OLD_IP:NEW_IP SERVER_2:OLD_IP:NEW_IP SERVER_3:OLD_IP:NEW_IP ] [-H] HAPROXY_1 HAPROXY_2 ]\n
    [ [-r] SERVER_1 SERVER_2 SERVER_3 ] [ [-H] HAPROXY_1 HAPROXY_2 ] \n
    [ [-m] SERVER_1 SERVER_2 SERVER_3 ] [ [-H] HAPROXY_1 HAPROXY_2 ] \n
    [ [-m] SERVER_1 SERVER_2 SERVER_3 ] [ [-H] HAPROXY_1 HAPROXY_2 ] '''
    
    parser = argparse.ArgumentParser(description="ECE Server Automation", usage=usage)

    parser.add_argument('-u', '--user', help='Tenant username for authentication', required=True)
    parser.add_argument('-p', '--password', help='Tenant password')
    parser.add_argument('-e', '--endpoint', help='Endpoint Server Name', required=True)
    parser.add_argument('-t', '--tenant', help='Tenant/Project name', required=True)
    parser.add_argument('-c', '--number_of_vms', help='Number of VMs')
    parser.add_argument('-s', '--server_prefix', help='Server Prefix for new server creation')
    parser.add_argument('-i', '--reassign_ip', metavar='server1:old_ip:new_ip server2:old_ip:new_ip', nargs='+', help='Reassign Floating IP', default=[])
    parser.add_argument('-d', '--delete_vms', metavar='server1 server2..', nargs='+', help='Delete/Terminate VMs', default=[])
    parser.add_argument('-H', '--haproxy', metavar='haproxy_1 haproxy_2..', nargs='+', help='haproxy endpoints', default = [])
    parser.add_argument('-l', '--add_to_lb', metavar='server1 server2..', nargs='+', help='Add VM to loadbalancer', default=[])
    parser.add_argument('-r', '--remove_from_lb', metavar='server1 server2..', nargs='+', help='Remove VM from loadbalancer', default=[])
    parser.add_argument('-m', '--maint', metavar='server1 server2..', nargs='+', help='Set server maintenance in load balancer', default=[])
    parser.add_argument('-a', '--activate', metavar='server1 server2..', nargs='+', help='Undo server maint in loadbalancer', default=[])
    parser.add_argument('-y', '--yes', help='Confirm Yes', action='store_true', default=False)
    parser.add_argument('-q', '--quiet', help='Quiet Mode', action='store_true', default=False)
    
    


    args = parser.parse_args()
    return args

'''Get token from the specificed username/password'''
def getStackToken(params, url):
    try:
        headers = {"Content-Type": "application/json"}
        conn = httplib.HTTPConnection(url)
        conn.request("POST", "/v2.0/tokens", params, headers)

        response = conn.getresponse()
        data = response.read()
        tokenData = json.loads(data)
        conn.close()
        return tokenData
    except Exception, e:
        print "Login Failed"
        sys.exit(1)

'''Get URL for endpoint services'''
def getURL(type):
    try:
        url_parse = urlparse(endpoint_urls[type])
        endpoint = url_parse[1]
        version_and_token = url_parse[2]
        result = {}
        result['endpoint'] = endpoint
        result['version_and_token'] = version_and_token
        return result
    except Exception, e:
        print "Error constructing URL"

'''Perform GETs from Stack Endpoints'''
def getFromStack(endpoint, uri, params2, headers2):
    try:
        print endpoint, uri
        conn = httplib.HTTPConnection(endpoint)
        conn.request("GET", "%s" % uri, params2, headers2)
        response = conn.getresponse()
        data = response.read()
        result = json.loads(data)
        conn.close()
        return result
    except Exception, e:
        print "Error getting data from ECE endpoint - %s" % e
    


'''Create Servers'''
def createVM(nt, no_of_instances, server_prefix):
    new_vms = {}
    servers = nt.servers.list()
    instance_id = []
    base_image_name = base_image[server_prefix]
    FLAVOR = base_image_flavor[server_prefix]
    base_id = images[base_image_name]
    start = 0
    
    for server in servers:
        server_name = server.name
        if server_name.startswith(server_prefix):
            id = server_name.split('-')
            try:
                instance_id.append(int(id[-1]))
            except ValueError:
                instance_id.append(0)
    if instance_id:
        start = max(instance_id)
    start = start + 1
    print "** Creating Servers\n"
    created_servers = ""

    for i in range(start, no_of_instances+start):
        instance_name = "%s-%s" % (server_prefix, str(i).zfill(3))
        try:
            t=nt.servers.create(image=base_id, flavor=FLAVOR, name=instance_name)
            new_vms[t.id] = instance_name
            if i == start:
                created_servers = instance_name
            else:
                created_servers = created_servers + ", %s" % instance_name
            
            print "%s - %s" % (t.id, instance_name)
        except Exception, e:
            print "Error creating server: %s" % e
    print "New Servers - %s" % created_servers
    return new_vms


'''Assign Floating IP'''
def assignIP(nt, new_vms):
    floating_ipiplist = []
    try:
        floating_iplist = nt.floating_ips.list()
    except Exception, e:
        print "Error getting floating ip list: %s" % e
        
    print "\n"
    print "** Assigning Floating IP \n"
    for floating_ip in floating_iplist:
        if floating_ip.instance_id == None:
            floating_ipiplist.append(floating_ip.ip)

    '''Assign IP for all the newly created VMs'''
    for id in new_vms:
        nt = client.Client(USER, PASS, TENANT, AUTH_URL, service_type="compute")
        while True:
            ip = ''
            if nt.servers.get(id).status == "ACTIVE":
                if floating_ipiplist:
                    ip = floating_ipiplist.pop()
                else:
                    floating_ip = nt.floating_ips.create()
                    ip = floating_ip.ip
                try:
                    a=nt.servers.add_floating_ip(id, ip)
                except Exception, e:
                    print "Error assigning floating IP: %s" % e
                print "Assigned IP - %s to Instance - %s" % (ip, new_vms[id])
                break
            #else:
            #    time.sleep(60)


def confirm(prompt=None, resp=False):
    if prompt is None:
        prompt = 'Confirm'

    if resp:
        prompt = '%s [%s]|%s: ' % (prompt, 'y', 'n')
    else:
        prompt = '%s [%s]|%s: ' % (prompt, 'n', 'y')
        
    while True:
        ans = raw_input(prompt)
        if not ans:
            return resp
        if ans not in ['y', 'Y', 'n', 'N']:
            print 'please enter y or n.'
            continue
        if ans == 'y' or ans == 'Y':
            return True
        if ans == 'n' or ans == 'N':
            return False


'''Delete Servers'''
def deleteVM(nt, servers, live_servers):
    server_to_be_deleted = {}
    duplicate_servers = []
    for server in servers:
        for id, live_server in live_servers.items():
            if server == live_server:
                if server_to_be_deleted:
                    if server in server_to_be_deleted:
                        duplicate_servers.append(server)
                    else:
                        server_to_be_deleted[server] = id
                else:
                    server_to_be_deleted[server] = id
    remove_ids = list(set(server_to_be_deleted) & set(duplicate_servers))
    for values in remove_ids:
        del server_to_be_deleted[values]

    for values  in duplicate_servers:
        print "Redundant server names found. Skipping Delete - %s" % values

    print '''** Deleting VM \n'''
    if server_to_be_deleted:
        for server in server_to_be_deleted:
            print "Deleted - %s" % server
            try:
                a=nt.servers.delete(server_to_be_deleted[server])
            except Exception, e:
                print "Error deleting server: %s" % e



'''Get Floating IP from Server ID'''
def getFloatingIP(server_id):
    try:
        floating_ip = nt.floating_ips.list()
       
        for records in floating_ip:
            if server_id == records.instance_id:
                return records.fixed_ip

    except Exception, e:
        print "Error getting floating ip for server: %s" % e

    return None




'''Get Fixed IP from floating IP'''
def getFixedIP(server_floating_ip):
    try:
        floating_ip = nt.floating_ips.list()
    except Exception, e:
        print "Error getting floatin ip list: %s" % e
        
    for records in floating_ip:
        if server_floating_ip in records.ip:
            return records.fixed_ip



    
def getKey(dic, val):
    try:
        return [key for key, value in dic.iteritems() if value == val][0]
    except Exception, e:
        return None


'''Add server to Load Balancer'''
def addToLB(configdata, servers, haproxies, live_servers):
    
    for haproxy in haproxies:
        print "-- HA Proxy Node: %s" % haproxy
        virtual_ip = getFixedIP(haproxy)
        '''Build LB Configs'''
        lb_configs = {}
        server_lb_configs = {}
        for records in configdata['nodes']:
            if 'haproxy' in records:
                server_prefix = records['hostname_prefix']
                virtual_rules = {}
                for rule in records['haproxy']:
                    rule_attr = {}
                    rule_attr['virtual_name'] = records['haproxy'][rule]['virtual_name']
                    #rule_attr['virtual_ip'] = records['haproxy'][rule]['virtual_ip']
                    rule_attr['virtual_ip'] = virtual_ip
                    rule_attr['virtual_port'] = records['haproxy'][rule]['virtual_port']
                    rule_attr['real_port'] = records['haproxy'][rule]['real_port']
                    virtual_rules[rule] = rule_attr
                    server_lb_configs[server_prefix] = virtual_rules

        for server_prefix in server_lb_configs:
            lb_final_config = {}
            for rules in server_lb_configs[server_prefix]:
                frontend = {}
                frontend['virtual_name'] = server_lb_configs[server_prefix][rules]['virtual_name']
                frontend['virtual_port'] = server_lb_configs[server_prefix][rules]['virtual_port']
                frontend['virtual_ip'] = server_lb_configs[server_prefix][rules]['virtual_ip']
                backend = {}
                real_servers = []

                for server in servers:
                    if server.startswith(server_prefix):
                        server_property = {}
                        id = getKey(live_servers, server)
                        if id:
                            fixed_ip = getFloatingIP(id)
                            server_property['name'] = server
                            server_property['ip'] = fixed_ip
                            real_servers.append(server_property)
                        else:
                            print "%s - Server not found" % server
                backend["real_port"] = server_lb_configs[server_prefix][rules]['real_port']
                backend["real_servers"] = real_servers

                if real_servers:
                    lb_final_config = {'frontend': frontend, 'backend': backend}
                    uri = "/addServer"                 
                    postToLB(lb_final_config, haproxy, uri)
                


'''LB socket commands'''
def doLBCommands(configdata, servers, haproxies, live_servers, cmd):
    for haproxy in haproxies:
        print '''-- Executing socket command "%s" in HA Proxy Node: %s''' % (cmd, haproxy)
        
        '''Build LB Configs'''
        
        server_lb_configs = {}
        for records in configdata['nodes']:
            server_prefix = records['hostname_prefix']
            virtual_rules = {}
            virtual_name = []
	    if 'haproxy' in records:
            	for rule in records['haproxy']:
                	virtual_name.append(records['haproxy'][rule]['virtual_name'])
            	server_lb_configs[server_prefix] = virtual_name

        for server_prefix in server_lb_configs:
            lb_configs = {}
            servers_matching = []
            for server in servers:
                if server.startswith(server_prefix):
                    servers_matching.append(server)

            for virtual_name in server_lb_configs[server_prefix]:
                lb_configs['virtual_name'] = virtual_name
                lb_configs['real_servers'] = servers_matching

                if servers_matching:
                    if cmd == 'disable':
                        uri = "/setServerMaint"
                    if cmd == 'enable' :
                        uri = "/unsetServerMaint"


                    postToLB(lb_configs, haproxy, uri)
                    
            

'''Remove Server from Load Balancer'''
def deleteFromLB(configdata, servers, haproxies, live_servers):
    for haproxy in haproxies:
        print "-- HA Proxy Node: %s" % haproxy

        '''Build LB Configs'''
        lb_configs = {}
        server_lb_configs = {}
        for records in configdata['nodes']:
            if 'haproxy' in records:
                server_prefix = records['hostname_prefix']
                virtual_rules = {}
                for rule in records['haproxy']:
                    rule_attr = {}
                    rule_attr['virtual_name'] = records['haproxy'][rule]['virtual_name']
                    rule_attr['real_port'] = records['haproxy'][rule]['real_port']
                    virtual_rules[rule] = rule_attr
                    server_lb_configs[server_prefix] = virtual_rules

        for server_prefix in server_lb_configs:
            lb_final_config = {}
            for rules in server_lb_configs[server_prefix]:
                lb_final_config['virtual_name'] = server_lb_configs[server_prefix][rules]['virtual_name']
                real_servers = []

                for server in servers:
                    if server.startswith(server_prefix):
                        server_property = {}
                        '''needed if haproxy configs will have to match regex till real server ip'''
                        '''Example - server haproxy_rs-007 192.168.0.191:80 check inter 2000 rise 2 fall 5'''
                        #id = getKey(live_servers, server)
                        #fixed_ip = getFloatingIP(id)
                        #server_property['ip'] = fixed_ip
                        server_property['name'] = server
                        real_servers.append(server_property)
                lb_final_config['real_port'] = server_lb_configs[server_prefix][rules]['real_port']
                lb_final_config['real_servers'] = real_servers
            
            if real_servers:
                uri = "/deleteServer"
                postToLB(lb_final_config, haproxy, uri)



'''Load Balancer - REST Calls'''
def postToLB(lb_confg, haproxy, uri):
    try:
        print "\n"
        print lb_confg
        url = '''http://%s:5000/%s''' % (haproxy, uri)
        headers = {'content-type': 'application/json'}
        data = json.dumps(lb_confg)
        clen = len(data)
        req = urllib2.Request(url, data, {'Content-Type': 'application/json', 'Content-Length': clen})
        base64string = base64.encodestring('%s:%s' % (USER, PASS)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)
        f = urllib2.urlopen(req)
        response = f.read()
        print response
        print "\n"
        f.close()
    except Exception, e:
        print "Error while making changes to haproxy - %s : %s" % (haproxy, e)

if __name__ == '__main__':
    configdata = readConfigs()
    options = setCommandOptions()
    base_url = ''
    live_Servers = {}
    
    if len(sys.argv) == 1:
        print 'No options specified. For Help: ./stackops -h | --help'
        parser.print_help()
        sys.exit(1)
    
    USER = options.user

    if not options.password:
        PASS = getpass.getpass()
    else:
        PASS = options.password


    base_url = "%s:5000" % options.endpoint
    TENANT = options.tenant
    token_params = '''{"auth":{"passwordCredentials":{"username": "%s", "password":"%s"}, "tenantName":"%s"}}''' % (USER, PASS, TENANT)

    tokenData = getStackToken(token_params, base_url)
    if 'error' in tokenData:
        print "Authentication Failed - %s" % tokenData
        sys.exit(1)


    LOGFILE = "stack_ops.log"
    old_stdout = sys.stdout

    if options.quiet:
        log_file = open(LOGFILE,"w")
        sys.stdout = log_file
    
    apitoken = tokenData['access']['token']['id']
    service_catalog = tokenData['access']['serviceCatalog']
    
    for keys in service_catalog:
        type = keys['type']
        url =  keys['endpoints'][0]['publicURL']
        endpoint_urls[type] = url
    
    '''Get Glance Image ID'''
    result = getURL('image')
    image_endpoint = result['endpoint']
    image_version_token = result['version_and_token']

    '''Get Images for the tenant'''
    uri = '''%s/images''' % image_version_token
    params2 = urllib.urlencode({})
    headers2 = { "X-Auth-Token":apitoken, "Content-type":"application/json" }
    images_tmp = getFromStack(image_endpoint, uri, params2, headers2)
    images_tmp_2 = images_tmp['images']

    images = {}
    for record in images_tmp_2:
        image_name = record['name']
        image_id = record['id']
        images[image_name] = image_id

    hostname_prefix = []
    for records in configdata:
        for attributes in configdata[records]:
            hostname_prefix.append(attributes['hostname_prefix'])
            base_image[attributes['hostname_prefix']] = attributes['base_image']
            if 'flavor' in attributes:
                base_image_flavor[attributes['hostname_prefix']] = attributes['flavor']
            else:
                base_image_flavor[attributes['hostname_prefix']] = FLAVOR
    AUTH_URL = '''http://%s:5000/v2.0/''' % options.endpoint
        
    try:
        nt = client.Client(USER, PASS, TENANT, AUTH_URL, service_type="compute")
    except Exception, e:
        print "Error authenticating ECE endpoint: %s" % e
        sys.exit(1)

    try:
        servers = nt.servers.list()
    except Exception, e:
        print "Error getting server list: %s" % e
    

    for server in servers:
        live_Servers[server.id] = server.name
        
    '''Condition for Creating VM'''
    if options.server_prefix:
        if options.number_of_vms > 0:
            if options.server_prefix in hostname_prefix:
                vm_ids = createVM(nt, int(options.number_of_vms), options.server_prefix)
                assignIP(nt, vm_ids)
                if options.haproxy:
                    new_vms = []
                    new_live_servers =  dict(vm_ids.items() + live_Servers.items())
                    for vals in vm_ids:
                        new_vms.append(vm_ids[vals])
                    
                    print "\n** Adding configs to HA Proxy - %s" % options.haproxy
                    addToLB(configdata, new_vms, options.haproxy, new_live_servers)
            else:
                print "Server Prefix not found in config.. Exiting"
                sys.exit(1)
        else:
            print '''Missing - ./stackops.py -u USER -p PASSWORD -e ENDPOINT -t TENANT [ [-s] SERVER_PREFIX [-c] NUMBER_OF_VMS ]'''


            

    '''Condition for Deleting VM'''
    if options.delete_vms:
        '''Remove from LB'''
        if not options.yes:
            if confirm(prompt='Delete VMs?', resp=False):
                print "\n** Deleting configs from HA Proxy - %s\n" % options.haproxy
                deleteFromLB(configdata, options.delete_vms, options.haproxy, live_Servers)
                deleteVM(nt, options.delete_vms, live_Servers)
        else:
            deleteFromLB(configdata, options.delete_vms, options.haproxy, live_Servers)
            deleteVM(nt, options.delete_vms, live_Servers)
        

        
    '''Add VM to Load Balancer'''
    ##if options.add_to_lb or options.haproxy:
    if options.add_to_lb:
        if options.haproxy:
            addToLB(configdata, options.add_to_lb, options.haproxy, live_Servers)
        else:
            print "Failed - Missing options : ./stackops.py -u USER -p PASSWORD -e ENDPOINT -t TENANT -H HAPROXY_ENDPOINT -l SERVER_1 SERVER_2 .."
        


    '''Delete VM from Load Balancer'''
    if options.remove_from_lb:
        if options.haproxy:
            print "\n** Deleting VM from HA Proxy - %s" % options.haproxy
            deleteFromLB(configdata, options.remove_from_lb, options.haproxy, live_Servers)
        else:
            print "Failed - Missing options : ./stackops.py -u USER -p PASSWORD -e ENDPOINT -t TENANT -H HAPROXY_ENDPOINT -r SERVER_1 SERVER_2 .."
        

    '''Re-Assign IP'''
    if options.reassign_ip:
        new_ip = {}
        old_ip = {}
        servers = []
        
        for records in options.reassign_ip:
            tmp = records.split(":")
            old_ip[tmp[0].strip()] = tmp[1].strip()
            new_ip[tmp[0].strip()] = tmp[2].strip()
            servers.append(tmp[0].strip())

        if options.haproxy:
            print "\n** Deleting any old IP from HA Proxy - %s" % options.haproxy
            deleteFromLB(configdata, options.remove_from_lb, servers, live_Servers)

        print "\n** Removing old IP address"
        for s in servers:
            id = getKey(live_Servers, s)
            try:
                a=nt.servers.remove_floating_ip(id, old_ip[s])
                print "Removed %s from %s" % (old_ip[s], s)
            except Exception, e:
                print "Error Removing IP %s from %s - %s" % (old_ip[s], s, e)
           


        print "\n** Assigning New IP address"
        for s in servers:
            id = getKey(live_Servers, s)

            try:
                a=nt.servers.add_floating_ip(id, new_ip[s])
                print "Assigned IP %s to %s" % (new_ip[s], s)
            except Exception, ex:
                print "Error Assigning IP %s to %s - %s" % (new_ip[s], s, ex)

        if options.haproxy:
            print "\n** Adding new IP to load balancer"
            addToLB(configdata, servers, options.haproxy, live_Servers)
        
        
    '''Set server maint in Loadbalancer'''
    if options.maint and options.haproxy:
        print "\n** Disabling server in load balancer"
        doLBCommands(configdata, options.maint, options.haproxy, live_Servers, "disable")
       

    '''Unset server maint in Loadbalancer'''
    if options.activate and options.haproxy:
        print "\n** Enabling server in load balancer"
        doLBCommands(configdata, options.activate, options.haproxy, live_Servers, "enable")


    if options.quiet:
        sys.stdout = old_stdout
        log_file.close()

