tunlr-style-dns-unblocking
==========================

Since Tunlr.net closed down unexpectedly, I decided to publish my ideas and findings on the subject of DNS unblocking. I used Tunlr for some time when I decided to develop my own, private DNS unblocking solution. I'm using a combination of Dnsmasq and HAProxy. You will have to compile HAProxy on your own if you don't get a version >= 1.5 using yum/apt-get.

See here for more information: 

- http://trick77.com/2014/04/02/netflix-dns-unblocking-without-sni-xbox-360-ps3-samsung-tv/

The "poor-mans-non-sni" is the recommended approach and contains a configuration file generator.

For more information, you may want to read:
- http://trick77.com/2014/03/01/tunlr-style-dns-unblocking-pandora-netflix-hulu-et-al/
- http://trick77.com/2014/03/02/dns-unblocking-using-dnsmasq-haproxy/
