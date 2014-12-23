from util import config_format
import os
def generate(json, catchall = True, test = True, base_ip = None):
    haproxy_bind_ip = json["haproxy_bind_ip"]
    server_options = json["server_options"]
    if base_ip == None:
        base_ip = json["base_ip"]
    current_ip = base_ip
    current_port = json["base_port"]

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

def generate_frontend_catchall_entry(dest_addr, mode):
    if (mode == 'http'):
        return config_format('use_backend b_catchall_' + mode + ' if { hdr(host) -i ' + dest_addr + ' }')
    
    elif (mode == 'https'):
        return config_format('use_backend b_catchall_' + mode + ' if { req_ssl_sni -i ' + dest_addr + ' }')
    
    return None


def generate_backend_catchall_entry(dest_addr, mode, port, server_options, override_dest_addr = None):
    result = None
    if (mode == 'http'):
        result = config_format('use-server ' + dest_addr + ' if { hdr(host) -i ' + dest_addr + ' }')
        if (override_dest_addr == None):
            result += config_format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
        
        else:
            result += config_format('server ' + dest_addr + ' ' + override_dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
        
    
    elif (mode == 'https'):
        result = config_format('use-server ' + dest_addr + ' if { req_ssl_sni -i ' + dest_addr + ' }')
        result += config_format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options + os.linesep)
    
    return result

def generate_global():
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


def generate_defaults():
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


def generate_deadend(mode):
    result = config_format('backend b_deadend_' + mode, False)
    if (mode == 'http'):
        result += config_format('mode http')
        result += config_format('option httplog')
        result += config_format('option accept-invalid-http-response')
        result += config_format('option http-server-close')
    
    elif (mode == 'https'):
        result += config_format('mode tcp')
        result += config_format('option tcplog')
    

    result += os.linesep
    return result


def generate_stats(stats, haproxy_bind_ip):
    if stats["password"] == "":
        stats["password"] = raw_input("Please enter a password for the HAproxy stats: ")
    result = config_format('listen stats', False)
    result += config_format('bind ' + haproxy_bind_ip + ':' + str(stats["port"]))
    result += config_format('mode http')
    result += config_format('stats enable')
    result += config_format('stats realm Protected\\ Area')
    result += config_format('stats uri /')
    result += config_format('stats auth ' + stats["user"] + ':' + stats["password"])
    result += os.linesep
    return result


def generate_frontend(proxy_name, mode, haproxy_bind_ip, current_port, is_catchall):
    result = config_format('frontend f_' + proxy_name + '_' + mode, False)
    result += config_format('bind ' + haproxy_bind_ip + ':' + str(current_port))

    if (mode == 'http'):
        result += config_format('mode http')
        result += config_format('option httplog')
        result += config_format('capture request header Host len 50')
        result += config_format('capture request header User-Agent len 150')
    
    elif (mode == 'https'):
        result += config_format('mode tcp')
        result += config_format('option tcplog')
        if (is_catchall):
            result += config_format('tcp-request inspect-delay 5s')
            result += config_format('tcp-request content accept if { req_ssl_hello_type 1 }')
        
    
    if (is_catchall):
        result += config_format('default_backend b_deadend_' + mode)
    
    else:
        result += config_format('default_backend b_' + proxy_name + '_' + mode)
    
    result += os.linesep
    return result


def generate_backend(proxy_name, mode, dest_addr, port, server_options, is_catchall):
    result = config_format('backend b_' + proxy_name + '_' + mode, False)

    if (mode == 'http'):
        result += config_format('mode http')
        result += config_format('option httplog')
        result += config_format('option accept-invalid-http-response')

    
    elif (mode == 'https'):
        result += config_format('mode tcp')
        result += config_format('option tcplog')
    

    if (not is_catchall):
        result += config_format('server ' + dest_addr + ' ' + dest_addr + ':' + str(port) + ' ' + server_options)
    
    return result + os.linesep