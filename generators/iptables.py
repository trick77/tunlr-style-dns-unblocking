def generate(json):

    iptables_location = json["iptables_location"]
    haproxy_bind_ip = json["haproxy_bind_ip"]
    current_ip = json["base_ip"]
    current_port = json["base_port"]

    iptables_content += generate_iptables('80', haproxy_bind_ip, current_ip, current_port, iptables_location)
    current_port += 1
    iptables_content += generate_iptables('443', haproxy_bind_ip, current_ip, current_port, iptables_location)
    current_port += 1

    for proxy in json["proxies"]:
        if proxy["enabled"] and not proxy["catchall"]:
            current_ip = long2ip(ip2long(current_ip) + 1)
            for mode in proxy["modes"]:
                iptables_content += generate_iptables(mode["port"], haproxy_bind_ip, current_ip, current_port, iptables_location)
                current_port += 1
            
def generate_iptables(port, haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location):
    result = iptables_location + ' -t nat -A PREROUTING -p tcp --dport ' + str(port) + ' -d ' + current_dnat_ip + ' -j DNAT --to-destination ' + 'haproxy_bind_ip' + ':' + str(current_dnat_port) + os.linesep
    result += iptables_location + ' -t nat -A POSTROUTING -p tcp --dport ' + str(current_dnat_port) + ' -j MASQUERADE' + os.linesep
    return result