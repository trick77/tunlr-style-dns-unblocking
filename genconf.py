import json as json2
import os
import sys
import re
import argparse
from socket import inet_ntoa, inet_aton
from struct import pack, unpack
INDENT = '  '
def get_contents(filename):
    with open(filename) as f:
        return f.read()
def put_contents(filename, data):
    with open(filename, 'w') as f:
        f.write(data)
def json_decode(json):
    json = re.sub("#(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|([\s\t]//.*)|(^//.*)#","",json)
    return json2.loads(json)

def long2ip(ip):
    return inet_ntoa(pack("!L", ip))

def ip2long(ip_addr):
    return unpack("!L", inet_aton(ip_addr))[0]

def generate_haproxy(json, catchall = True, test = True, base_ip = None):
    haproxy_bind_ip = json["haproxy_bind_ip"]
    server_options = json["server_options"]
    if base_ip == None:
        base_ip = json["dnat_base_ip"]
    current_ip = base_ip
    current_port = json["dnat_base_port"]

    haproxy_content = generate_global()
    haproxy_content += generate_defaults()
    

    if catchall:
        http_port = 80
        https_port = 443
    else:
        http_port = current_port
        https_port = current_port + 1

    haproxy_catchall_frontend_content = generate_frontend('catchall', 'http', haproxy_bind_ip, http_port, True)
    haproxy_catchall_backend_content = generate_backend('catchall', 'http', None, None, None, True)

    haproxy_catchall_frontend_ssl_content = generate_frontend('catchall', 'https', haproxy_bind_ip, https_port, True)
    haproxy_catchall_backend_ssl_content = generate_backend('catchall', 'https', None, None, None, True)

    if (json["stats"]["enabled"]):
        haproxy_content += generate_stats(json["stats"], haproxy_bind_ip)

    for proxy in json["proxies"]:
        if proxy["enabled"]:
            if catchall or (not catchall and proxy["catchall"]):
                for mode in proxy["modes"]:
                    if (mode["mode"] == 'http'):
                        haproxy_catchall_frontend_content += generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_content += generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"],server_options)
                    elif (mode["mode"] == 'https'):
                        haproxy_catchall_frontend_ssl_content += generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_ssl_content += generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"],server_options)
    if test:
        haproxy_catchall_frontend_content += generate_frontend_catchall_entry('proxy-test.trick77.com', 'http')
        haproxy_catchall_backend_content += generate_backend_catchall_entry('proxy-test.trick77.com', 'http', '80', server_options, 'trick77.com')


    haproxy_content += haproxy_catchall_frontend_content + os.linesep
    haproxy_content += haproxy_catchall_backend_content
    haproxy_content += haproxy_catchall_frontend_ssl_content + os.linesep
    haproxy_content += haproxy_catchall_backend_ssl_content

    current_port += 2

    if not catchall:
        for proxy in json["proxies"]:
            if proxy["enabled"] and not proxy["catchall"]:
                for mode in proxy["modes"]:
                    haproxy_content += generate_frontend(proxy["name"], mode["mode"], haproxy_bind_ip, current_port, False)
                    haproxy_content += generate_backend(proxy["name"], mode["mode"], proxy["dest_addr"], mode["port"], server_options, False)
                    current_port += 1


    haproxy_content += generate_deadend('http')
    haproxy_content += generate_deadend('https')

    return haproxy_content

def generate_dnsmasq(json, catchall = True, test = True, base_ip = None):
    haproxy_bind_ip = json["haproxy_bind_ip"]
    if base_ip == None:
        base_ip = json["dnat_base_ip"]
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
    current_dnat_ip = json["dnat_base_ip"]
    current_dnat_port = json["dnat_base_port"]

    dnsmasq_content = generate_dnsmasq(json, catchall=False, base_ip = current_dnat_ip)
    haproxy_content = generate_haproxy(json, catchall=False, base_ip = current_dnat_ip)
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
    current_loopback_ip = json["loopback_base_ip"]
    current_dnat_port = json["dnat_base_port"]

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



def generate_frontend_catchall_entry(dest_addr, mode) :
    if (mode == 'http') :
        return config_format('use_backend b_catchall_' + mode + ' if { hdr(host) -i ' + dest_addr + ' }')
    
    elif (mode == 'https') :
        return config_format('use_backend b_catchall_' + mode + ' if { req_ssl_sni -i ' + dest_addr + ' }')
    
    return None


def generate_backend_catchall_entry(dest_addr, mode, port, server_options, override_dest_addr = None) :
    result = None
    if (mode == 'http') :
        result = config_format('use-server ' + dest_addr + ' if { hdr(host) -i ' + dest_addr + ' }')
        if (override_dest_addr == None) :
            result += config_format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
        
        else :
            result += config_format('server ' + dest_addr + ' ' + override_dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
        
    
    elif (mode == 'https') :
        result = config_format('use-server ' + dest_addr + ' if { req_ssl_sni -i ' + dest_addr + ' }')
        result += config_format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
    
    return result


def generate_dns(dest_addr, current_dnat_ip) :
    result = 'address=/' + dest_addr + '/' + current_dnat_ip
    return result + os.linesep


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


def generate_global() :
    result = config_format('global', False)
    result += config_format('daemon')
    result += config_format('maxconn 20000')
    result += config_format('user haproxy')
    result += config_format('group haproxy')
    result += config_format('stats socket /var/run/haproxy.sock mode 0600 level admin')
    result += config_format('log /dev/log local0 debug')
    result += config_format('pidfile /var/run/haproxy.pid')
    result += config_format('spread-checks 5')
    result += os.linesep
    return result


def generate_defaults() :
    result = config_format('defaults', False)
    result += config_format('maxconn 19500')
    result += config_format('log global')
    result += config_format('mode http')
    result += config_format('option httplog')
    result += config_format('option abortonclose')
    result += config_format('option http-server-close')
    result += config_format('option persist')
    result += config_format('timeout connect 20s')
    result += config_format('timeout client 120s')
    result += config_format('timeout server 120s')
    result += config_format('timeout queue 120s')
    result += config_format('timeout check 10s')
    result += config_format('retries 3')
    result += os.linesep
    return result


def generate_deadend(mode) :
    result = config_format('backend b_deadend_' + mode, False)
    if (mode == 'http') :
        result += config_format('mode http')
        result += config_format('option httplog')
        result += config_format('option accept-invalid-http-response')
        result += config_format('option http-server-close')
    
    elif (mode == 'https') :
        result += config_format('mode tcp')
        result += config_format('option tcplog')
    

    result += os.linesep
    return result


def generate_stats(stats, haproxy_bind_ip) :
    result = config_format('listen stats', False)
    result += config_format('bind ' + haproxy_bind_ip + ':' + str(stats["port"]))
    result += config_format('mode http')
    result += config_format('stats enable')
    result += config_format('stats realm Protected\\ Area')
    result += config_format('stats uri /')
    result += config_format('stats auth ' + stats["user"] + ':' + stats["password"])
    result += os.linesep
    return result


def generate_frontend(proxy_name, mode, haproxy_bind_ip, current_dnat_port, is_catchall) :
    result = config_format('frontend f_' + proxy_name + '_' + mode, False)
    result += config_format('bind ' + haproxy_bind_ip + ':' + str(current_dnat_port))

    if (mode == 'http') :
        result += config_format('mode http')
        result += config_format('option httplog')
        result += config_format('capture request header Host len 50')
        result += config_format('capture request header User-Agent len 150')
    
    elif (mode == 'https') :
        result += config_format('mode tcp')
        result += config_format('option tcplog')
        if (is_catchall) :
            result += config_format('tcp-request inspect-delay 5s')
            result += config_format('tcp-request content accept if { req_ssl_hello_type 1 }')
        
    
    if (is_catchall) :
        result += config_format('default_backend b_deadend_' + mode)
    
    else :
        result += config_format('default_backend b_' + proxy_name + '_' + mode)
    
    result += os.linesep
    return result


def generate_backend(proxy_name, mode, dest_addr, port, server_options, is_catchall) :
    result = config_format('backend b_' + proxy_name + '_' + mode, False)

    if (mode == 'http') :
        result += config_format('mode http')
        result += config_format('option httplog')
        result += config_format('option accept-invalid-http-response')

    
    elif (mode == 'https') :
        result += config_format('mode tcp')
        result += config_format('option tcplog')
    

    if (not is_catchall) :
        result += config_format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options)
    
    return result + os.linesep


def config_format(line, do_ident = True) :
    if (do_ident) :
        return INDENT + line + os.linesep
    
    return line + os.linesep
    
def main(cmd, skipdns, skipproxy):
    if skipproxy:
        haproxy_filename = None
    else:
        haproxy_filename = "haproxy.conf"
    if skipdns:
        dnsmasq_filename = None
    else:
        dnsmasq_filename = "dnsmasq-haproxy.conf"

    if cmd == "non-sni":
        create_non_sni_config("config.json", haproxy_filename, dnsmasq_filename, 'iptables-haproxy.sh')
    elif cmd == "local":
        create_local_non_sni_config("config.json", haproxy_filename, 'netsh-haproxy.cmd', 'hosts-haproxy.txt', 'rinetd-haproxy.conf')
    elif cmd == "pure-sni":
        create_pure_sni_config("config.json", haproxy_filename, dnsmasq_filename)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate configuration files to setup a tunlr style smart DNS")
    parser.add_argument("cmd", choices=["non-sni", "local", "pure-sni"], type=str, help="The type of configuration files to generate")
    parser.add_argument("-d", "--no-dns", action="store_true", help="Skip generating the DNS configuration file")
    parser.add_argument("-p", "--no-proxy", action="store_true", help="Skip generating the haproxy configuration file")
    args = parser.parse_args()
    main(args.cmd, args.no_dns, args.no_proxy)
