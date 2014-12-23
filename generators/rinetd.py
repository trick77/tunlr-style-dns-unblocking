import os
from util import long2ip, ip2long
def generate(json):

    iptables_location = json["iptables_location"]
    public_ip = json["public_ip"]
    current_ip = json["base_ip"]
    current_port = json["base_port"]

    rinetd_content = generate_rinetd('80', public_ip, current_ip, current_port)
    current_port += 1
    rinetd_content += generate_rinetd('443', public_ip, current_ip, current_port)
    current_port += 1

    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            current_ip = long2ip(ip2long(current_ip) + 1)
            for mode in proxy["modes"]:
                rinetd_content += generate_rinetd(mode["port"], public_ip, current_ip, current_port)
                current_port += 1
    return rinetd_content
            


def generate_rinetd(port, public_ip, current_ip, current_port):
    result = current_ip + ' ' + str(port) + ' ' + public_ip + ' ' + str(current_port) + os.linesep
    return result

