from util import long2ip, ip2long
import os
def generate(json, catchall = True, test = True):
    public_ip = json["public_ip"]
    current_ip = json["base_ip"]
    dnsmasq_content = ""
    for proxy in json["proxies"]:
        if proxy["enabled"]:
            if catchall:
                dnsmasq_content += generate_dns(proxy["dest_addr"], public_ip)
            elif proxy["catchall"]:
                dnsmasq_content += generate_dns(proxy["dest_addr"], current_ip)

        
    if test:
        if catchall:
            dnsmasq_content += generate_dns('proxy-test.trick77.com', public_ip)
            dnsmasq_content += generate_dns('dns-test.trick77.com', public_ip)
        else:
            dnsmasq_content += generate_dns('proxy-test.trick77.com', current_ip)
            dnsmasq_content += generate_dns('dns-test.trick77.com', current_ip)

    if not catchall:
        for proxy in json["proxies"]:
            if proxy["enabled"] and not proxy["catchall"]:
                current_ip = long2ip(ip2long(current_ip) + 1)
                dnsmasq_content += generate_dns(proxy["dest_addr"], current_ip)

    return dnsmasq_content

def generate_dns(dest_addr, current_ip):
    result = 'address=/' + dest_addr + '/' + current_ip
    return result + os.linesep

