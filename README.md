tunlr-style-dns-unblocking
==========================

Since Tunlr.net closed down unexpectedly, I decided to publish my ideas and findings on the subject of DNS unblocking. I used Tunlr for some time when I decided to develop my own, private DNS unblocking solution. I'm using a combination of Dnsmasq and HAProxy. You will have to compile HAProxy on your own if you don't get a version >= 1.5 using yum/apt-get. Make sure the JSON-Library is available for PHP.

THIS IS NOT A TUTORIAL!

The configuration generator (genconf.php) has two modes:
- pure-sni (Simple Setup)
- non-sni (Advanced Setup)
- local (Advanced Setup)

Please drop a comment in http://trick77.com/2014/04/17/dns-unblocking-generator-update/ once you've managed to set up your own DNS-unblocking service!

Want to add a service to config.json or found an outdated configuration section? Please send a pull request with the  updated configuration.

#### pure-sni (Simple Setup)

Use this setup if all your multimedia players are SNI-capable.

Requires a U.S. based server (a 128 MB low end VPS is enough) and preferrably a local Dnsmasq DNS forwarder. DD-WRT routers or a Raspberry Pi will do. You could run Dnsmasq on the remote server as well but it's not recommended for security and latency reasons.

In pure-sni mode, you don't have to worry about the dnat_base_ip, dnat_base_port and loopback_base_ip options. Those options are not used, just leave them at their defaults. Make sure iptables_location points to the iptables executable and enter your VPS' IP address in haproxy_bind_ip. Make sure the ports 80 and 443 on your VPS are not being used by some other software like Apache2. Use ```netstat -tulpn``` to make sure.

For this mode, call the generator like this:
```php genconf.php pure-sni```

The generator will create two files based on the information in json.config:
- haproxy.conf
- dnsmasq-haproxy.conf
 
I'm currently running a HAProxy-based DNS-unblocker on 208.110.82.54 so you can start with your DNS forwarder setup first and add your own HAProxy server later. 

See here for additional information: 

- http://trick77.com/2014/03/01/tunlr-style-dns-unblocking-pandora-netflix-hulu-et-al/
- http://trick77.com/2014/03/02/dns-unblocking-using-dnsmasq-haproxy/

#### non-sni (Advanced Setup)

non-sni mode enables DNS-unblocking for multimedia players (or applications) which can't handle SNI but still using just a single IP address using some netfilter trickery. See here for more information on this mode:
http://trick77.com/2014/04/02/netflix-dns-unblocking-without-sni-xbox-360-ps3-samsung-tv/

#### local (Advanced Setup)

local mode enables DNS-unblocking on a single device which can't handle SNI but still using just a single IP address and without using another server on the network.
The generator will create four files based on the information in json.config:
- haproxy.conf (for the remote server)
- netsh-haproxy.cmd (for Windows)
- rinetd-haproxy.conf (for Linux)
- hosts-haproxy.txt (for Linux/Windows)

For Windows:
- Run notepad as administrator and open %SystemRoot%\system32\drivers\etc\hosts (usually c:\windows\system32\drivers\etc\hosts), copy the contents of hosts-haproxy.txt
- Run netsh-haproxy.cmd as administrator

- To reset: delete contents of %SystemRoot%\system32\drivers\etc\hosts, run as administrator 'netsh interface portproxy reset'

For Linux:
- Run 'sudo tee -a /etc/hosts < hosts-haproxy.txt' (or append hots-haproxy.txt to /etc/hosts)
- Run 'sudo cp rinetd-haproxy.conf /etc/rinetd.conf && sudo service rinetd start'

- To reset: 'sudo sed -i '/### GENERATED/d' /etc/hosts' and 'sudo service rinetd stop && sudo rm /etc/rinetd.conf'

