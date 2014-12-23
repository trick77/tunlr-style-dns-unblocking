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
    if (json["stats"]["enabled"]):
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



def create_non_sni_config(json_in_filename, haproxy_out_filename=None, dnsmasq_out_filename=None, iptables_out_filename=None) :
    content = get_contents(json_in_filename)
    json = json_decode(content)

    iptables_location = json["iptables_location"]
    haproxy_bind_ip = json["haproxy_bind_ip"]
    current_dnat_ip = json["base_ip"]
    current_dnat_port = json["base_port"]

    dnsmasq_content = generate_dnsmasq(json, catchall=False, base_ip=current_dnat_ip)
    haproxy_content = generate_haproxy(json, catchall=False, base_ip=current_dnat_ip)
    iptables_content = ""

    print 'Make sure the following IP addresses are available as virtual interfaces on your Ddnsmasq-server:'
    print current_dnat_ip

    iptables_content += generate_iptables('80', haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location)
    current_dnat_port += 1
    iptables_content += generate_iptables('443', haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location)
    current_dnat_port += 1

    json = json_decode(content)
    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            current_dnat_ip = long2ip(ip2long(current_dnat_ip) + 1)
            for mode in proxy["modes"]:
                iptables_content += generate_iptables(mode["port"], haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location)
                current_dnat_port += 1
            print current_dnat_ip

    
    print 'If you are using an inbound firewall on ' + haproxy_bind_ip + ':'
    if (json["stats"]["enabled"]) :
        print iptables_location + ' -A INPUT -p tcp -m state --state NEW -d ' + haproxy_bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT'
    
    print iptables_location + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + haproxy_bind_ip + ' --dports ' + str(json["dnat_base_port"]) + ':' + "--current_dnat_port" + ' -j ACCEPT'
    
    if haproxy_out_filename != None:
        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename 
    if dnsmasq_out_filename != None:
        put_contents(dnsmasq_out_filename, dnsmasq_content)
        print 'File generated: ' + dnsmasq_out_filename
    if iptables_out_filename != None:
        put_contents(iptables_out_filename, iptables_content)
        print 'File generated: ' + iptables_out_filename


def create_local_non_sni_config(json_in_filename, haproxy_out_filename=None, netsh_out_filename = None, hosts_out_filename = None, rinetd_out_filename = None) :
    content = get_contents(json_in_filename)
    json = json_decode(content)

    iptables_location = json["iptables_location"]
    haproxy_bind_ip = json["haproxy_bind_ip"]
    current_loopback_ip = json["base_ip"]
    current_dnat_port = json["base_port"]

    netsh_content = ''
    rinetd_content = ''
    hosts = dict()

    haproxy_content = generate_haproxy(json, catchall=False, base_ip=current_loopback_ip)
    

    for proxy in json["proxies"]:
        if proxy["enabled"] and proxy["catchall"]:
            add_hosts(hosts, proxy["dest_addr"], current_loopback_ip)

    add_hosts(hosts, 'proxy-test.trick77.com', current_loopback_ip)
    add_hosts(hosts, 'dns-test.trick77.com', current_loopback_ip)


    netsh_content += generate_netsh('80', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
    rinetd_content += generate_rinetd('80', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
    current_dnat_port += 1
    netsh_content += generate_netsh('443', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
    rinetd_content += generate_rinetd('443', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
    current_dnat_port += 1

    for proxy in json["proxies"]:
        if (proxy["enabled"] and not proxy["catchall"]) :
            current_loopback_ip = long2ip(ip2long(current_loopback_ip) + 1)
            for mode in proxy["modes"]:
                netsh_content += generate_netsh(mode["port"], haproxy_bind_ip, current_loopback_ip, current_dnat_port)
                rinetd_content += generate_rinetd(mode["port"], haproxy_bind_ip, current_loopback_ip, current_dnat_port)
                current_dnat_port += 1
            
            add_hosts(hosts, proxy["dest_addr"], current_loopback_ip)

    print 'If you are using an inbound firewall on ' + haproxy_bind_ip + ':'
    if (json["stats"]["enabled"]) :
        print iptables_location + ' -A INPUT -p tcp -m state --state NEW -d ' + haproxy_bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT'
    
    print iptables_location + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + haproxy_bind_ip + ' --dports ' + str(json["dnat_base_port"]) + ':' + "--current_dnat_port" + ' -j ACCEPT' 
    
    if haproxy_out_filename != None:
        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename
    if hosts_out_filename != None:
        put_contents(hosts_out_filename,  generate_hosts_content(hosts))
        print 'File generated: ' + hosts_out_filename
    if netsh_out_filename != None:
        put_contents(netsh_out_filename, netsh_content)
        print 'File generated: ' + netsh_out_filename
    if rinetd_out_filename != None:
        put_contents(rinetd_out_filename, rinetd_content)
        print 'File generated: ' + rinetd_out_filename



def add_hosts(hosts, dest_addr, current_loopback_ip) :
    if(current_loopback_ip in hosts) :
        hosts[current_loopback_ip].append(dest_addr)
    else :
        hosts[current_loopback_ip] = [dest_addr]



def generate_netsh(port, haproxy_bind_ip, current_loopback_ip, current_dnat_port) :
    result = 'netsh interface portproxy add v4tov4 protocol=tcp listenport=' + str(port) + ' listenaddress=' + current_loopback_ip + ' connectaddress=' + 'haproxy_bind_ip' + ' connectport=' + str(current_dnat_port) + os.linesep
    return result


def generate_rinetd(port, haproxy_bind_ip, current_loopback_ip, current_dnat_port) :
    result = current_loopback_ip + ' ' + str(port) + ' ' + haproxy_bind_ip + ' ' + str(current_dnat_port) + os.linesep
    return result


def generate_hosts_content(hosts) :
    result = ''
    for ip, list in hosts.items():
        result += ip + ' ' + " ".join(list) + ' ### GENERATED ' + os.linesep
    
    return result


def generate_iptables(port, haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location) :
    result = iptables_location + ' -t nat -A PREROUTING -p tcp --dport ' + str(port) + ' -d ' + current_dnat_ip + ' -j DNAT --to-destination ' + 'haproxy_bind_ip' + ':' + str(current_dnat_port) + os.linesep
    result += iptables_location + ' -t nat -A POSTROUTING -p tcp --dport ' + str(current_dnat_port) + ' -j MASQUERADE' + os.linesep
    return result

    
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
