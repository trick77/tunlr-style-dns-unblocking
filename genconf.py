import os
import sys
import argparse
from util import *

from generators import *
from generators.util import *




def create_pure_sni_config(json_in_filename, haproxy_out_filename=None, dnsmasq_out_filename=None):
    content = get_contents(json_in_filename)
    json = json_decode(content)
    iptables_location = json["iptables_location"]
    haproxy_bind_ip = json["haproxy_bind_ip"]
    dnsmasq_content = generate_dnsmasq(json)

    haproxy_content = generate_haproxy(json)

    print 'If you are using an inbound firewall on ' + haproxy_bind_ip + ':' + os.linesep
    if json["stats"]["enabled"]:
        print iptables_location + ' -A INPUT -p tcp -m state --state NEW -d ' + haproxy_bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT'
    
    print iptables_location + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + haproxy_bind_ip + ' --dports ' + "80" + ':' + "443" + ' -j ACCEPT'
    
    if haproxy_out_filename != None:
        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename

    if dnsmasq_out_filename != None:
        put_contents(dnsmasq_out_filename, dnsmasq_content)
        print 'File generated: ' + dnsmasq_out_filename

    print ""
    print '***********************************************************************************************'
    print 'Caution: it\'s not recommended but it\'s possible to run a (recursive) DNS forwarder on your'
    print 'remote server ' + haproxy_bind_ip + '. If you leave the DNS port wide open to everyone,'
    print 'your server will get terminated sooner or later because of abuse (DDoS amplification attacks).'
    print '***********************************************************************************************'



def create_non_sni_config(json_in_filename, haproxy_out_filename=None, dnsmasq_out_filename=None, iptables_out_filename=None):
    content = get_contents(json_in_filename)
    json = json_decode(content)

    current_ip = json["base_ip"]

    dnsmasq_content = generate_dnsmasq(json, catchall=False, base_ip=current_ip)
    haproxy_content = generate_haproxy(json, catchall=False, base_ip=current_ip)
    iptables_content = generate_iptables(json)

    print 'Make sure the following IP addresses are available as virtual interfaces on your Ddnsmasq-server:'
    print current_ip
    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            current_ip = long2ip(ip2long(current_ip) + 1)
            print current_ip

    
    print_firewall(json)

    if haproxy_out_filename != None:
        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename 
    if dnsmasq_out_filename != None:
        put_contents(dnsmasq_out_filename, dnsmasq_content)
        print 'File generated: ' + dnsmasq_out_filename
    if iptables_out_filename != None:
        put_contents(iptables_out_filename, iptables_content)
        print 'File generated: ' + iptables_out_filename


def create_local_non_sni_config(json_in_filename, haproxy_out_filename=None, netsh_out_filename = None, hosts_out_filename = None, rinetd_out_filename = None):
    content = get_contents(json_in_filename)
    json = json_decode(content)

    netsh_content = generate_netsh(json)
    rinetd_content = generate_rinetd(json)
    hosts_content = generate_hosts(json)
    haproxy_content = generate_haproxy(json, catchall=False)

    print_firewall(json)
    
    if haproxy_out_filename != None:
        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename
    if hosts_out_filename != None:
        put_contents(hosts_out_filename,  hosts_content)
        print 'File generated: ' + hosts_out_filename
    if netsh_out_filename != None:
        put_contents(netsh_out_filename, netsh_content)
        print 'File generated: ' + netsh_out_filename
    if rinetd_out_filename != None:
        put_contents(rinetd_out_filename, rinetd_content)
        print 'File generated: ' + rinetd_out_filename
def print_firewall(json):
    bind_ip = json["haproxy_bind_ip"]
    print 'If you are using an inbound firewall on ' + bind_ip + ':'
    if json["stats"]["enabled"]:
        print json["iptables_location"] + ' -A INPUT -p tcp -m state --state NEW -d ' + bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT'
    
    print json["iptables_location"] + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + bind_ip + ' --dports ' + str(json["base_port"]) + ':' + str(port_range(json)) + ' -j ACCEPT' 
    
def port_range(json):
    start = json["base_port"]
    end = start + 2
    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            end += len(proxy["modes"])
    return start, end-1



    
def main(cmd, skipdns, skipproxy):
    if skipproxy:
        haproxy_filename = None
    else:
        haproxy_filename = "haproxy.conf"
    if skipdns:
        dnsmasq_filename = None
    else:
        dnsmasq_filename = "dnsmasq-haproxy.conf"

    if cmd == "pure-sni":
        create_pure_sni_config("config.json", haproxy_filename, dnsmasq_filename)
    elif cmd == "non-sni":
        create_non_sni_config("config.json", haproxy_filename, dnsmasq_filename, 'iptables-haproxy.sh')
    elif cmd == "local":
        create_local_non_sni_config("config.json", haproxy_filename, 'netsh-haproxy.cmd', 'hosts-haproxy.txt', 'rinetd-haproxy.conf')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate configuration files to setup a tunlr style smart DNS")
    parser.add_argument("cmd", choices=["non-sni", "local", "pure-sni"], type=str, help="The type of configuration files to generate")
    parser.add_argument("-d", "--no-dns", action="store_true", help="Skip generating the DNS configuration file")
    parser.add_argument("-p", "--no-proxy", action="store_true", help="Skip generating the haproxy configuration file")
    args = parser.parse_args()
    main(args.cmd, args.no_dns, args.no_proxy)
