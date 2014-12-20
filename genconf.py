import json as json2
import os
import sys
import re
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
class GenConf:
    def create_pure_sni_config(self, json_in_filename, haproxy_out_filename='haproxy.conf', dnsmasq_out_filename='dnsmasq-haproxy.conf'):
        content = get_contents(json_in_filename)
        json = json_decode(content)
        iptables_location = json["iptables_location"]
        server_options = json["server_options"]
        haproxy_bind_ip = json["haproxy_bind_ip"]
        dnsmasq_content = ""

        haproxy_content = self.generate_global()
        haproxy_content += self.generate_defaults()

        haproxy_catchall_frontend_content = self.generate_frontend('catchall', 'http', haproxy_bind_ip, 80, True)
        haproxy_catchall_backend_content = self.generate_backend('catchall', 'http', None, None, None, True)

        haproxy_catchall_frontend_ssl_content = self.generate_frontend('catchall', 'https', haproxy_bind_ip, 443, True)
        haproxy_catchall_backend_ssl_content = self.generate_backend('catchall', 'https', None, None, None, True)

        if (json["stats"]["enabled"]):
            haproxy_content += self.generate_stats(json["stats"], haproxy_bind_ip)
        

        for proxy in json["proxies"]: 
            if (proxy["enabled"]):
                for mode in proxy["modes"]:
                    if (mode["mode"] == 'http'):
                        haproxy_catchall_frontend_content += self.generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_content += self.generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"],server_options)
                    elif (mode["mode"] == 'https'):
                        haproxy_catchall_frontend_ssl_content += self.generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_ssl_content += self.generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"],server_options)
                
                dnsmasq_content += self.generate_dns(proxy["dest_addr"], haproxy_bind_ip)
            

        test = self.add_test(haproxy_bind_ip, server_options)
        haproxy_catchall_frontend_content += test[0]
        haproxy_catchall_backend_content += test[1]
        dnsmasq_content += test[2]

        haproxy_content += haproxy_catchall_frontend_content + os.linesep
        haproxy_content += haproxy_catchall_backend_content
        haproxy_content += haproxy_catchall_frontend_ssl_content + os.linesep
        haproxy_content += haproxy_catchall_backend_ssl_content

        haproxy_content += self.generate_deadend('http')
        haproxy_content += self.generate_deadend('https')

        print 'If you are using an inbound firewall on ' + haproxy_bind_ip + ':' + os.linesep
        if (json["stats"]["enabled"]):
            print iptables_location + ' -A INPUT -p tcp -m state --state NEW -d ' + haproxy_bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT' + os.linesep
        
        print iptables_location + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + haproxy_bind_ip + ' --dports ' + "80" + ':' + "443" + ' -j ACCEPT' + os.linesep
        

        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename + os.linesep

        put_contents(dnsmasq_out_filename, dnsmasq_content)
        print 'File generated: ' + dnsmasq_out_filename + os.linesep

        print ""
        print '***********************************************************************************************' + os.linesep
        print 'Caution: it\'s not recommended but it\'s possible to run a (recursive) DNS forwarder on your' + os.linesep
        print 'remote server ' + haproxy_bind_ip + '. If you leave the DNS port wide open to everyone,' + os.linesep
        print 'your server will get terminated sooner or later because of abuse (DDoS amplification attacks).' + os.linesep
        print '***********************************************************************************************' + os.linesep

    

    def create_non_sni_config(self, json_in_filename, haproxy_out_filename = 'haproxy.conf', dnsmasq_out_filename = 'dnsmasq-haproxy.conf', iptables_out_filename = 'iptables-haproxy.sh') :
        content = get_contents(json_in_filename)
        json = json_decode(content)
        iptables_location = json["iptables_location"]
        server_options = json["server_options"]
        haproxy_bind_ip = json["haproxy_bind_ip"]
        dnsmasq_content = ''
        iptables_content = ''

        haproxy_content = self.generate_global()
        haproxy_content += self.generate_defaults()

        current_dnat_ip = json["dnat_base_ip"]
        current_dnat_port = json["dnat_base_port"]

        haproxy_catchall_frontend_content = self.generate_frontend('catchall', 'http', haproxy_bind_ip, current_dnat_port, True)
        haproxy_catchall_backend_content = self.generate_backend('catchall', 'http', None, None, None, True)

        haproxy_catchall_frontend_ssl_content = self.generate_frontend('catchall', 'https', haproxy_bind_ip, current_dnat_port + 1, True)
        haproxy_catchall_backend_ssl_content = self.generate_backend('catchall', 'https', None, None, None, True)

        if (json["stats"]["enabled"]) :
            haproxy_content += self.generate_stats(json["stats"], haproxy_bind_ip)
        

        for proxy in json["proxies"]:
            if proxy["enabled"] and proxy["catchall"]:
                for mode in proxy["modes"]:
                    if (mode["mode"] == 'http') :
                        haproxy_catchall_frontend_content += self.generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_content += self.generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"], server_options)
                    
                    elif (mode["mode"] == 'https') :
                        haproxy_catchall_frontend_ssl_content += self.generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_ssl_content += self.generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"], server_options)
                    
                
                dnsmasq_content += self.generate_dns(proxy["dest_addr"], current_dnat_ip)
            
        

        test = self.add_test(current_dnat_ip, server_options)
        haproxy_catchall_frontend_content += test[0]
        haproxy_catchall_backend_content += test[1]
        dnsmasq_content += test[2]

        print 'Make sure the following IP addresses are available as virtual interfaces on your Ddnsmasq-server:' + os.linesep

        haproxy_content += haproxy_catchall_frontend_content + os.linesep
        haproxy_content += haproxy_catchall_backend_content
        haproxy_content += haproxy_catchall_frontend_ssl_content + os.linesep
        haproxy_content += haproxy_catchall_backend_ssl_content
        iptables_content += self.generate_iptables('80', haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location)
        current_dnat_port += 1
        iptables_content += self.generate_iptables('443', haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location)
        current_dnat_port += 1
        print current_dnat_ip + os.linesep

        json = json_decode(content)
        for proxy in json["proxies"]:
            if proxy["enabled"] and not proxy["catchall"]:
                current_dnat_ip = long2ip(ip2long(current_dnat_ip) + 1)
                for mode in proxy["modes"]:
                    haproxy_content += self.generate_frontend(proxy["name"], mode["mode"], haproxy_bind_ip, current_dnat_port, False)
                    iptables_content += self.generate_iptables(mode["port"], haproxy_bind_ip, current_dnat_ip, current_dnat_port,
                        iptables_location)
                    haproxy_content += self.generate_backend(proxy["name"], mode["mode"], proxy["dest_addr"], mode["port"], server_options, False)
                    current_dnat_port += 1
                
                dnsmasq_content += self.generate_dns(proxy["dest_addr"], current_dnat_ip)
                print current_dnat_ip + os.linesep
            
        

        haproxy_content += self.generate_deadend('http')
        haproxy_content += self.generate_deadend('https')

        
        print 'If you are using an inbound firewall on ' + haproxy_bind_ip + ':' + os.linesep
        if (json["stats"]["enabled"]) :
            print iptables_location + ' -A INPUT -p tcp -m state --state NEW -d ' + haproxy_bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT' + os.linesep
        
        print iptables_location + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + haproxy_bind_ip + ' --dports ' + str(json["dnat_base_port"]) + ':' + "--current_dnat_port" + ' -j ACCEPT' + os.linesep
        

        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename + os.linesep

        put_contents(dnsmasq_out_filename, dnsmasq_content)
        print 'File generated: ' + dnsmasq_out_filename + os.linesep

        put_contents(iptables_out_filename, iptables_content)
        print 'File generated: ' + iptables_out_filename + os.linesep
    

    def create_local_non_sni_config(self, json_in_filename, haproxy_out_filename = 'haproxy.conf', netsh_out_filename = 'netsh-haproxy.cmd', hosts_out_filename = 'hosts-haproxy.txt', rinetd_out_filename = 'rinetd-haproxy.conf') :
        content = get_contents(json_in_filename)
        json = json_decode(content)
        iptables_location = json["iptables_location"]
        server_options = json["server_options"]
        haproxy_bind_ip = json["haproxy_bind_ip"]
        netsh_content = ''
        rinetd_content = ''
        hosts = dict()

        haproxy_content = self.generate_global()
        haproxy_content += self.generate_defaults()

        current_loopback_ip = json["loopback_base_ip"]
        current_dnat_port = json["dnat_base_port"]

        haproxy_catchall_frontend_content = self.generate_frontend('catchall', 'http', haproxy_bind_ip, current_dnat_port, True)
        haproxy_catchall_backend_content = self.generate_backend('catchall', 'http', None, None, None, True)

        haproxy_catchall_frontend_ssl_content = self.generate_frontend('catchall', 'https', haproxy_bind_ip, current_dnat_port + 1, True)
        haproxy_catchall_backend_ssl_content = self.generate_backend('catchall', 'https', None, None, None, True)

        if (json["stats"]["enabled"]) :
            haproxy_content += self.generate_stats(json["stats"], haproxy_bind_ip)
        

        for proxy in json["proxies"]:
            if proxy["enabled"] and proxy["catchall"]:
                for mode in proxy["modes"]:
                    if (mode["mode"] == 'http') :
                        haproxy_catchall_frontend_content += self.generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_content += self.generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"],
                            server_options)
                    
                    elif (mode["mode"] == 'https') :
                        haproxy_catchall_frontend_ssl_content += self.generate_frontend_catchall_entry(proxy["dest_addr"], mode["mode"])
                        haproxy_catchall_backend_ssl_content += self.generate_backend_catchall_entry(proxy["dest_addr"], mode["mode"], mode["port"],
                            server_options)
                    
                
                self.add_hosts(hosts, proxy["dest_addr"], current_loopback_ip)
            
        

        test = self.add_test(current_loopback_ip, server_options)
        haproxy_catchall_frontend_content += test[0]
        haproxy_catchall_backend_content += test[1]
        self.add_hosts(hosts, 'proxy-test.trick77.com', current_loopback_ip)
        self.add_hosts(hosts, 'dns-test.trick77.com', current_loopback_ip)

        haproxy_content += haproxy_catchall_frontend_content + os.linesep
        haproxy_content += haproxy_catchall_backend_content
        haproxy_content += haproxy_catchall_frontend_ssl_content + os.linesep
        haproxy_content += haproxy_catchall_backend_ssl_content
        netsh_content += self.generate_netsh('80', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
        rinetd_content += self.generate_rinetd('80', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
        current_dnat_port += 1
        netsh_content += self.generate_netsh('443', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
        rinetd_content += self.generate_rinetd('443', haproxy_bind_ip, current_loopback_ip, current_dnat_port)
        current_dnat_port += 1

        json = json_decode(content)
        for proxy in json["proxies"]:
            if (proxy["enabled"] and not proxy["catchall"]) :
                current_loopback_ip = long2ip(ip2long(current_loopback_ip) + 1)
                for mode in proxy["modes"]:
                    haproxy_content += self.generate_frontend(proxy["name"], mode["mode"], haproxy_bind_ip, current_dnat_port, False)
                    netsh_content += self.generate_netsh(mode["port"], haproxy_bind_ip, current_loopback_ip, current_dnat_port)
                    rinetd_content += self.generate_rinetd(mode["port"], haproxy_bind_ip, current_loopback_ip, current_dnat_port)
                    haproxy_content += self.generate_backend(proxy["name"], mode["mode"], proxy["dest_addr"], mode["port"], server_options, False)
                    current_dnat_port += 1
                
                self.add_hosts(hosts, proxy["dest_addr"], current_loopback_ip)
            
        

        haproxy_content += self.generate_deadend('http')
        haproxy_content += self.generate_deadend('https')

        print 'If you are using an inbound firewall on ' + haproxy_bind_ip + ':' + os.linesep
        if (json["stats"]["enabled"]) :
            print iptables_location + ' -A INPUT -p tcp -m state --state NEW -d ' + haproxy_bind_ip + ' --dport ' + str(json["stats"]["port"]) + ' -j ACCEPT' + os.linesep
        
        print iptables_location + ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' + haproxy_bind_ip + ' --dports ' + str(json["dnat_base_port"]) + ':' + "--current_dnat_port" + ' -j ACCEPT' + os.linesep
        

        put_contents(haproxy_out_filename, haproxy_content)
        print 'File generated: ' + haproxy_out_filename + os.linesep

        put_contents(hosts_out_filename,  self.generate_hosts_content(hosts))
        print 'File generated: ' + hosts_out_filename + os.linesep

        put_contents(netsh_out_filename, netsh_content)
        print 'File generated: ' + netsh_out_filename + os.linesep

        put_contents(rinetd_out_filename, rinetd_content)
        print 'File generated: ' + rinetd_out_filename + os.linesep
    

    def add_test(self, catchall_ip, server_options) :
        haproxy_catchall_frontend_content = self.generate_frontend_catchall_entry('proxy-test.trick77.com', 'http')
        haproxy_catchall_backend_content = self.generate_backend_catchall_entry('proxy-test.trick77.com', 'http', '80',
            server_options, 'trick77.com')
        dnsmasq_content = self.generate_dns('proxy-test.trick77.com', catchall_ip)
        dnsmasq_content += self.generate_dns('dns-test.trick77.com', catchall_ip)
        return (haproxy_catchall_frontend_content, haproxy_catchall_backend_content, dnsmasq_content)
    

    def generate_frontend_catchall_entry(self, dest_addr, mode) :
        if (mode == 'http') :
            return self.format('use_backend b_catchall_' + mode + ' if { hdr(host) -i ' + dest_addr + ' }')
        
        elif (mode == 'https') :
            return self.format('use_backend b_catchall_' + mode + ' if { req_ssl_sni -i ' + dest_addr + ' }')
        
        return None
    

    def generate_backend_catchall_entry(self, dest_addr, mode, port, server_options, override_dest_addr = None) :
        result = None
        if (mode == 'http') :
            result = self.format('use-server ' + dest_addr + ' if { hdr(host) -i ' + dest_addr + ' }')
            if (override_dest_addr == None) :
                result += self.format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
            
            else :
                result += self.format('server ' + dest_addr + ' ' + override_dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
            
        
        elif (mode == 'https') :
            result = self.format('use-server ' + dest_addr + ' if { req_ssl_sni -i ' + dest_addr + ' }')
            result += self.format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
        
        return result
    

    def generate_dns(self, dest_addr, current_dnat_ip) :
        result = 'address=/' + dest_addr + '/' + current_dnat_ip
        return result + os.linesep
    

    def add_hosts(self, hosts, dest_addr, current_loopback_ip) :
        if(current_loopback_ip in hosts) :
            hosts[current_loopback_ip].append(dest_addr)
        else :
            hosts[current_loopback_ip] = [dest_addr]
    
    

    def generate_netsh(self, port, haproxy_bind_ip, current_loopback_ip, current_dnat_port) :
        result = 'netsh interface portproxy add v4tov4 protocol=tcp listenport=' + str(port) + ' listenaddress=' + current_loopback_ip + ' connectaddress=' + 'haproxy_bind_ip' + ' connectport=' + str(current_dnat_port) + os.linesep
        return result
    

    def generate_rinetd(self, port, haproxy_bind_ip, current_loopback_ip, current_dnat_port) :
        result = current_loopback_ip + ' ' + str(port) + ' ' + haproxy_bind_ip + ' ' + str(current_dnat_port) + os.linesep
        return result
    

    def generate_hosts_content(self, hosts) :
        result = ''
        for ip, list in hosts.items():
            result += ip + ' ' + " ".join(list) + ' ### GENERATED ' + os.linesep
        
        return result
    

    def generate_iptables(self, port, haproxy_bind_ip, current_dnat_ip, current_dnat_port, iptables_location) :
        result = iptables_location + ' -t nat -A PREROUTING -p tcp --dport ' + str(port) + ' -d ' + current_dnat_ip + ' -j DNAT --to-destination ' + 'haproxy_bind_ip' + ':' + str(current_dnat_port) + os.linesep
        result += iptables_location + ' -t nat -A POSTROUTING -p tcp --dport ' + str(current_dnat_port) + ' -j MASQUERADE' + os.linesep
        return result
    

    def generate_global(self) :
        result = self.format('global', False)
        result += self.format('daemon')
        result += self.format('maxconn 20000')
        result += self.format('user haproxy')
        result += self.format('group haproxy')
        result += self.format('stats socket /var/run/haproxy.sock mode 0600 level admin')
        result += self.format('log /dev/log local0 debug')
        result += self.format('pidfile /var/run/haproxy.pid')
        result += self.format('spread-checks 5')
        result += os.linesep
        return result
    

    def generate_defaults(self) :
        result = self.format('defaults', False)
        result += self.format('maxconn 19500')
        result += self.format('log global')
        result += self.format('mode http')
        result += self.format('option httplog')
        result += self.format('option abortonclose')
        result += self.format('option http-server-close')
        result += self.format('option persist')
        result += self.format('timeout connect 20s')
        result += self.format('timeout client 120s')
        result += self.format('timeout server 120s')
        result += self.format('timeout queue 120s')
        result += self.format('timeout check 10s')
        result += self.format('retries 3')
        result += os.linesep
        return result
    

    def generate_deadend(self, mode) :
        result = self.format('backend b_deadend_' + mode, False)
        if (mode == 'http') :
            result += self.format('mode http')
            result += self.format('option httplog')
            result += self.format('option accept-invalid-http-response')
            result += self.format('option http-server-close')
        
        elif (mode == 'https') :
            result += self.format('mode tcp')
            result += self.format('option tcplog')
        

        result += os.linesep
        return result
    

    def generate_stats(self, stats, haproxy_bind_ip) :
        result = self.format('listen stats', False)
        result += self.format('bind ' + haproxy_bind_ip + ':' + str(stats["port"]))
        result += self.format('mode http')
        result += self.format('stats enable')
        result += self.format('stats realm Protected\\ Area')
        result += self.format('stats uri /')
        result += self.format('stats auth ' + stats["user"] + ':' + stats["password"])
        result += os.linesep
        return result
    

    def generate_frontend(self, proxy_name, mode, haproxy_bind_ip, current_dnat_port, is_catchall) :
        result = self.format('frontend f_' + proxy_name + '_' + mode, False)
        result += self.format('bind ' + haproxy_bind_ip + ':' + str(current_dnat_port))

        if (mode == 'http') :
            result += self.format('mode http')
            result += self.format('option httplog')
            result += self.format('capture request header Host len 50')
            result += self.format('capture request header User-Agent len 150')
        
        elif (mode == 'https') :
            result += self.format('mode tcp')
            result += self.format('option tcplog')
            if (is_catchall) :
                result += self.format('tcp-request inspect-delay 5s')
                result += self.format('tcp-request content accept if { req_ssl_hello_type 1 }')
            
        
        if (is_catchall) :
            result += self.format('default_backend b_deadend_' + mode)
        
        else :
            result += self.format('default_backend b_' + proxy_name + '_' + mode)
        
        result += os.linesep
        return result
    

    def generate_backend(self, proxy_name, mode, dest_addr, port, server_options, is_catchall) :
        result = self.format('backend b_' + proxy_name + '_' + mode, False)

        if (mode == 'http') :
            result += self.format('mode http')
            result += self.format('option httplog')
            result += self.format('option accept-invalid-http-response')

        
        elif (mode == 'https') :
            result += self.format('mode tcp')
            result += self.format('option tcplog')
        

        if (not is_catchall) :
            result += self.format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options)
        
        return result + os.linesep
    

    def format(self,line, do_ident = True) :
        if (do_ident) :
            return INDENT + line + os.linesep
        
        return line + os.linesep
    

if len(sys.argv) == 2:
    g = GenConf()
    arg1 = sys.argv[1].lower()
    if arg1 == "non-sni":
        g.create_non_sni_config("config.json")
    elif arg1 == "local":
        g.create_local_non_sni_config("config.json")
    elif arg1 == "pure-sni":
        g.create_pure_sni_config("config.json")
    else:
        print "Missing/wrong argument, use pure-sni (simple setup), non-sni (advanced setup),  local (advanced setup)"

else:
    print "Missing/wrong argument, use pure-sni (simple setup), non-sni (advanced setup),  local (advanced setup)"
