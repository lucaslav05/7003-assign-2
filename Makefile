RUN = sudo python3 main.py -i any -c 1 -f
IP = bcit.ca

arp:
	$(RUN) arp

udp4:
	$(RUN) 'ip and udp'

tcp4:
	$(RUN) 'ip and tcp'

udp6:
	$(RUN) 'ip6 and udp'

tcp6:
	$(RUN) 'ip6 and tcp'

icmp:
	$(RUN) icmp

icmp6:
	$(RUN) icmp6

ip6:
	$(RUN) ip6

dns:
	$(RUN) 'udp port 53 or tcp port 53'

p-arp:
	sudo arping -c 1 10.0.0.1

p-udp:
	echo "Hello, World!" | ncat --udp 192.168.0.1 12345

p-udp6:
	echo "Hello, World!" | ncat --udp 2001:db8::1 12345

p-tcp:
	curl http://$(IP)

p-tcp6:
	curl -6 http://ipv6.google.com

p-icmp:
	ping -c 1 $(IP)

p-icmp6:
	ping6 -c 1 google.com



p-dns:
	nslookup $(IP) -retry=10
