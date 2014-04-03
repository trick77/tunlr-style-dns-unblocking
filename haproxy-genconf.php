<?php

class HAProxy_GenConf {

    var $INDENT = '  ';

    function run($json_in_filename, $haproxy_out_filename = 'haproxy.conf', $dnsmasq_out_filename = 'dnsmasq-haproxy.conf', $iptables_out_filename = 'iptables-haproxy.conf') {
        $content = file_get_contents($json_in_filename);
        $json = json_decode($content);
        $iptables_location = $json->iptables_location;
        $server_options = $json->server_options;
        $haproxy_bind_ip = $json->haproxy_bind_ip;
        $dnsmasq_content = '';
        $iptables_content = '';

        $haproxy_content = $this->generate_global();
        $haproxy_content .= $this->generate_defaults();

        $current_dnat_ip = $json->dnat_base_ip;
        $current_dnat_port = $json->dnat_base_port;

        $haproxy_catchall_frontend_content = $this->generate_frontend('catchall', 'http', $haproxy_bind_ip, $current_dnat_port, TRUE);
        $haproxy_catchall_backend_content = $this->generate_backend('catchall', 'http', NULL, NULL, NULL, TRUE);

        $haproxy_catchall_frontend_ssl_content = $this->generate_frontend('catchall', 'https', $haproxy_bind_ip, $current_dnat_port + 1, TRUE);
        $haproxy_catchall_backend_ssl_content = $this->generate_backend('catchall', 'https', NULL, NULL, NULL, TRUE);

        if ($json->stats->enabled) {
            $haproxy_content .= $this->generate_stats($json->stats, $haproxy_bind_ip);
        }

        $has_catchall = FALSE;
        while ($proxy = array_shift($json->proxies)) {
            if ($proxy->enabled && $proxy->catchall) {
                while ($mode = array_shift($proxy->modes)) {
                    $has_catchall = TRUE;
                    if ($mode->mode === 'http') {
                        $haproxy_catchall_frontend_content .= $this->generate_frontend_catchall_entry($proxy->dest_addr, $mode->mode);
                        $haproxy_catchall_backend_content .= $this->generate_backend_catchall_entry($proxy->dest_addr, $mode->mode, $mode->port,
                            $server_options);
                    }
                    else if ($mode->mode === 'https') {
                        $haproxy_catchall_frontend_ssl_content .= $this->generate_frontend_catchall_entry($proxy->dest_addr, $mode->mode);
                        $haproxy_catchall_backend_ssl_content .= $this->generate_backend_catchall_entry($proxy->dest_addr, $mode->mode, $mode->port,
                            $server_options);
                    }
                }
                $dnsmasq_content .= $this->generate_dns($proxy->dest_addr, $current_dnat_ip);
            }
        }

        echo 'Make sure the following IP addresses are available as virtual interfaces on your Ddnsmasq-server:' . PHP_EOL;

        if ($has_catchall) {
            $haproxy_content .= $haproxy_catchall_frontend_content . PHP_EOL;
            $haproxy_content .= $haproxy_catchall_backend_content;
            $haproxy_content .= $haproxy_catchall_frontend_ssl_content . PHP_EOL;
            $haproxy_content .= $haproxy_catchall_backend_ssl_content;
            $iptables_content .= $this->generate_iptables('80', $haproxy_bind_ip, $current_dnat_ip, $current_dnat_port, $iptables_location);
            $current_dnat_port++;
            $iptables_content .= $this->generate_iptables('443', $haproxy_bind_ip, $current_dnat_ip, $current_dnat_port, $iptables_location);
            $current_dnat_port++;
            echo $current_dnat_ip . PHP_EOL;
        }

        $json = json_decode($content);
        while ($proxy = array_shift($json->proxies)) {
            if ($proxy->enabled && ! $proxy->catchall) {
                $current_dnat_ip = long2ip(ip2long($current_dnat_ip) + 1);
                while ($mode = array_shift($proxy->modes)) {
                    $haproxy_content .= $this->generate_frontend($proxy->name, $mode->mode, $haproxy_bind_ip, $current_dnat_port, FALSE);
                    $iptables_content .= $this->generate_iptables($mode->port, $haproxy_bind_ip, $current_dnat_ip, $current_dnat_port,
                        $iptables_location);
                    $haproxy_content .= $this->generate_backend($proxy->name, $mode->mode, $proxy->dest_addr, $mode->port, $server_options, FALSE);
                    $current_dnat_port++;
                }
                $dnsmasq_content .= $this->generate_dns($proxy->dest_addr, $current_dnat_ip);
                echo $current_dnat_ip . PHP_EOL;

                $index ++;
            }
        }

        if ($has_catchall) {
            $haproxy_content .= $this->generate_deadend('http');
            $haproxy_content .= $this->generate_deadend('https');
        }

        echo PHP_EOL;
        echo 'If you are using an inbound firewall on ' . $haproxy_bind_ip . ':' . PHP_EOL;
        if ($json->stats->enabled) {
            echo $iptables_location . ' -A INPUT -p tcp -m state --state NEW -d ' . $haproxy_bind_ip . ' --dport ' . $json->stats->port . ' -j ACCEPT' . PHP_EOL;
        }
        echo $iptables_location . ' -A INPUT -p tcp -m state --state NEW -m multiport -d ' . $haproxy_bind_ip . ' --dports ' . $json->dnat_base_port . ':' .
             --$current_dnat_port . ' -j ACCEPT' . PHP_EOL;
        echo PHP_EOL;

        file_put_contents($haproxy_out_filename, $haproxy_content);
        echo 'File generated: ' . $haproxy_out_filename . PHP_EOL;

        file_put_contents($dnsmasq_out_filename, $dnsmasq_content);
        echo 'File generated: ' . $dnsmasq_out_filename . PHP_EOL;

        file_put_contents($iptables_out_filename, $iptables_content);
        echo 'File generated: ' . $iptables_out_filename . PHP_EOL;
    }

    function generate_frontend_catchall_entry($dest_addr, $mode) {
        if ($mode === 'http') {
            return $this->format('use_backend b_catchall_' . $mode . ' if { hdr(host) -i ' . $dest_addr . ' }');
        }
        else if ($mode === 'https') {
            return $this->format('use_backend b_catchall_' . $mode . ' if { req_ssl_sni -i ' . $dest_addr . ' }');
        }
        return NULL;
    }

    function generate_backend_catchall_entry($dest_addr, $mode, $port, $server_options) {
        $result = NULL;
        if ($mode === 'http') {
            $result = $this->format('use-server ' . $dest_addr . ' if { hdr(host) -i ' . $dest_addr . ' }');
            $result .= $this->format('server ' . $dest_addr . ' ' . $dest_addr . ':' . $port . ' ' . $server_options . PHP_EOL);
        }
        else if ($mode === 'https') {
            $result = $this->format('use-server ' . $dest_addr . ' if { req_ssl_sni -i ' . $dest_addr . ' }');
            $result .= $this->format('server ' . $dest_addr . ' ' . $dest_addr . ':' . $port . ' ' . $server_options . PHP_EOL);
        }
        return $result;
    }

    function generate_dns($dest_addr, $current_dnat_ip) {
        $result = 'address=/' . $dest_addr . '/' . $current_dnat_ip;
        return $result . PHP_EOL;
    }

    function generate_iptables($port, $haproxy_bind_ip, $current_dnat_ip, $current_dnat_port, $iptables_location) {
        $result = $iptables_location . ' -t nat -A PREROUTING -p tcp --dport ' . $port . ' -d ' . $current_dnat_ip . ' -j DNAT --to-destination ' .
             $haproxy_bind_ip . ':' . $current_dnat_port . PHP_EOL;
        $result .= $iptables_location . ' -t nat -A POSTROUTING -p tcp --dport ' . $current_dnat_port . ' -j MASQUERADE' . PHP_EOL;
        return $result;
    }

    function generate_global() {
        $result = $this->format('global', FALSE);
        $result .= $this->format('daemon');
        $result .= $this->format('maxconn 20000');
        $result .= $this->format('user haproxy');
        $result .= $this->format('group haproxy');
        $result .= $this->format('stats socket /var/run/haproxy.sock mode 0600 level admin');
        $result .= $this->format('log /dev/log local0 debug');
        $result .= $this->format('pidfile /var/run/haproxy.pid');
        $result .= $this->format('spread-checks 5');
        $result .= PHP_EOL;
        return $result;
    }

    function generate_defaults() {
        $result = $this->format('defaults', FALSE);
        $result .= $this->format('maxconn 19500');
        $result .= $this->format('log global');
        $result .= $this->format('mode http');
        $result .= $this->format('option httplog');
        $result .= $this->format('option abortonclose');
        $result .= $this->format('option http-server-close');
        $result .= $this->format('option persist');
        $result .= $this->format('timeout connect 20s');
        $result .= $this->format('timeout client 120s');
        $result .= $this->format('timeout server 120s');
        $result .= $this->format('timeout queue 120s');
        $result .= $this->format('timeout check 10s');
        $result .= $this->format('retries 3');
        $result .= PHP_EOL;
        return $result;
    }

    function generate_deadend($mode) {
        $result = $this->format('backend b_deadend_' . $mode, FALSE);
        $result .= $this->format('log global');
        if ($mode === 'http') {
            $result .= $this->format('mode http');
            $result .= $this->format('option httplog');
            $result .= $this->format('option accept-invalid-http-response');
            $result .= $this->format('option http-server-close');
        }
        else if ($mode === 'https') {
            $result .= $this->format('mode tcp');
            $result .= $this->format('option tcplog');
        }

        $result .= PHP_EOL;
        return $result;
    }

    function generate_stats($stats, $haproxy_bind_ip) {
        $result = $this->format('listen stats', FALSE);
        $result .= $this->format('bind ' . $haproxy_bind_ip . ':' . $stats->port);
        $result .= $this->format('mode http');
        $result .= $this->format('stats enable');
        $result .= $this->format('stats realm Protected\\ Area');
        $result .= $this->format('stats uri /');
        $result .= $this->format('stats auth ' . $stats->user . ':' . $stats->password);
        $result .= PHP_EOL;
        return $result;
    }

    function generate_frontend($proxy_name, $mode, $haproxy_bind_ip, $current_dnat_port, $is_catchall) {
        $result = $this->format('frontend f_' . $proxy_name . '_' . $mode, FALSE);
        $result .= $this->format('bind ' . $haproxy_bind_ip . ':' . $current_dnat_port);
        $result .= $this->format('log global');

        if ($mode === 'http') {
            $result .= $this->format('mode http');
            $result .= $this->format('option httplog');
            $result .= $this->format('capture request header Host len 50');
            $result .= $this->format('capture request header User-Agent len 150');
        }
        else if ($mode === 'https') {
            $result .= $this->format('mode tcp');
            $result .= $this->format('option tcplog');
            if ($is_catchall) {
                $result .= $this->format('tcp-request inspect-delay 5s');
                $result .= $this->format('tcp-request content accept if { req_ssl_hello_type 1 }');
            }
        }
        if ($is_catchall) {
            $result .= $this->format('default_backend b_deadend_' . $mode);
        }
        else {
            $result .= $this->format('default_backend b_' . $proxy_name . '_' . $mode);
        }
        $result .= PHP_EOL;
        return $result;
    }

    function generate_backend($proxy_name, $mode, $dest_addr, $port, $server_options, $is_catchall) {
        $result = $this->format('backend b_' . $proxy_name . '_' . $mode, FALSE);
        $result .= $this->format('log global');

        if ($mode === 'http') {
            $result .= $this->format('mode http');
            $result .= $this->format('option httplog');
            $result .= $this->format('option accept-invalid-http-response');

        }
        else if ($mode === 'https') {
            $result .= $this->format('mode tcp');
            $result .= $this->format('option tcplog');
        }

        if (! $is_catchall) {
            $result .= $this->format('server ' . $dest_addr . ' ' . $dest_addr . ':' . $port . ' ' . $server_options);
        }
        return $result . PHP_EOL;
    }

    function format($line, $do_ident = TRUE) {
        if ($do_ident) {
            return $this->INDENT . $line . PHP_EOL;
        }
        return $line . PHP_EOL;
    }
}

$g = new HAProxy_GenConf();
$g->run('config.json');

?>
