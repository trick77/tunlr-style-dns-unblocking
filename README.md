tunlr-style-dns-unblocking
==========================

Since Tunlr.net closed down unexpectedly this week, I decided to publish my ideas and findings on the subject of DNS unblocking. I used Tunlr for some time when I decided to develop my own, private DNS unblocking solution last year.

See here for more information: http://trick77.com/2014/03/01/tunlr-style-dns-unblocking-pandora-netflix-hulu-et-al/

I also included a working "poor man's" DNS unblocking sample configuration using just a single IP address. This should work fine with SNI-capable web browsers/devices but totally won't work with non-SNI-capable devices.

See here for more information and a running proof of concept server / Dnsmasq DNS forwarding configuration: http://trick77.com/2014/03/02/dns-unblocking-using-dnsmasq-haproxy/

| File | Description          |
| ------------- | ----------- |
| haproxy.conf      | Sample configuration using a combination of SNI and non-SNI backends which will work with non-SNI-capable devices as well. Won't run without modification. Requires around 20 different IP addresses.|
| poor-mans-haproxy.conf     | Working sample configuration using a single IP address. Won't work with non-SNI-capable devices. This will work greatly on a low-end $15/year virtual private server for you and your friends.    |
| poor-mans-dnsmasq.txt | Matching Dnsmasq configuration for the poor-mans-haproxy.conf |
| haproxy-genconf.php | Experimental, advanced stuff allowing non-SNI devices like Playstation 3, XBox360 to work using a single, public IP address thanks to DNATing |
| config.json | Configuration input file for haproxy-genconf.php |

