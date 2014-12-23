import os
from util import long2ip, ip2long
def generate(json):
    haproxy_bind_ip = json["haproxy_bind_ip"]
    current_ip = json["base_ip"]
    current_port = json["base_port"]

    netsh_content = generate_netsh('80', haproxy_bind_ip, current_ip, current_port)
    current_port += 1
    netsh_content += generate_netsh('443', haproxy_bind_ip, current_ip, current_port)
    current_port += 1

    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            current_ip = long2ip(ip2long(current_ip) + 1)
            for mode in proxy["modes"]:
                netsh_content += generate_netsh(mode["port"], haproxy_bind_ip, current_ip, current_port)
                current_port += 1
    return netsh_content
            

def generate_netsh(port, haproxy_bind_ip, current_ip, current_port):
    result = 'netsh interface portproxy add v4tov4 protocol=tcp listenport=' + str(port) + ' listenaddress=' + current_ip + ' connectaddress=' + 'haproxy_bind_ip' + ' connectport=' + str(current_port) + os.linesep
    return result