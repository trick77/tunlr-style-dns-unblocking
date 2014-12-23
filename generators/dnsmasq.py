from util import long2ip, ip2long
import os
def generate(json, catchall = True, test = True):
    haproxy_bind_ip = json["haproxy_bind_ip"]
    base_ip = json["base_ip"]
    current_dnat_ip = base_ip
    dnsmasq_content = ""
    for proxy in json["proxies"]:
        if proxy["enabled"]:
            if catchall:
                dnsmasq_content += generate_dns(proxy["dest_addr"], haproxy_bind_ip)
            elif proxy["catchall"]:
                dnsmasq_content += generate_dns(proxy["dest_addr"], current_dnat_ip)

        
    if test:
        if catchall:
            dnsmasq_content += generate_dns('proxy-test.trick77.com', haproxy_bind_ip)
            dnsmasq_content += generate_dns('dns-test.trick77.com', haproxy_bind_ip)
        else:
            dnsmasq_content += generate_dns('proxy-test.trick77.com', base_ip)
            dnsmasq_content += generate_dns('dns-test.trick77.com', base_ip)

    if not catchall:
        for proxy in json["proxies"]:
            if proxy["enabled"] and not proxy["catchall"]:
                current_dnat_ip = long2ip(ip2long(current_dnat_ip) + 1)
                dnsmasq_content += generate_dns(proxy["dest_addr"], current_dnat_ip)

    return dnsmasq_content

def generate_dns(dest_addr, current_dnat_ip) :
    result = 'address=/' + dest_addr + '/' + current_dnat_ip
    return result + os.linesep

