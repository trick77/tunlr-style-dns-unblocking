from util import long2ip, ip2long
import os
def generate(json, test = True):
    current_ip = json["base_ip"]
    hosts = dict()
    for proxy in json["proxies"]:
        if proxy["enabled"] and proxy["catchall"]:
            add_hosts(hosts, proxy["dest_addr"], current_ip)

            

        
    if test:
        add_hosts(hosts, 'proxy-test.trick77.com', current_ip)
        add_hosts(hosts, 'dns-test.trick77.com', current_ip)

    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            current_ip = long2ip(ip2long(current_ip) + 1)
            add_hosts(hosts, proxy["dest_addr"], current_ip)

    return generate_hosts_content(hosts)

def add_hosts(hosts, dest_addr, current_loopback_ip):
    if(current_loopback_ip in hosts):
        hosts[current_loopback_ip].append(dest_addr)
    else:
        hosts[current_loopback_ip] = [dest_addr]

def generate_hosts_content(hosts):
    result = ''
    for ip, list in hosts.items():
        result += ip + ' ' + " ".join(list) + ' ### GENERATED ' + os.linesep
    
    return result

