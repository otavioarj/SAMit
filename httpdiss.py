#!/usr/bin/python  
# Simple ARP MitM tool developed as an exercise  
# Author: Otavio Augusto otavioarj$at$gmail.com
# At Public Domain if, and only if, the author remain unchanged or a clear reference is made to him =]
# This code completely depends on Scapy http://www.secdev.org/projects/scapy 

from threading import Thread
import sys, logging, re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# HTTP Stream class, used to store: File transfered,last TCP.seq + inclement
#  File transfered can be either a HTTP Body or structured file, like ones formated as JPG, PE32.
#  Inclement is 
class hstream:
	hfile=''
	nextseq=0
	frange=0

#HTTP Data
def hdata(data):
	hparse=re.search('\r\n\r\n(.+?)', data)
	if hparse:
		rdata=hparse.group(1) # Data, just after the HTTP Response Header
		return rdata
#	else
#		return ''



#HTTPRequest Handler
def hrequest (src,dst,ack,data):
	hparse=re.search('/(.+?) HTTP/1.1\z', data)
	if not hparse:		
		hparse=re.search(' ^/(.+?) HTTP', data)
	if not hparse:
		fname='none'
	else:
		fname=hparse.group(1)
		print fname
	newconn=hstream()
	newconn.hfile= open(str(src)+"-"+str(dst)+"."+fname, "a")
	if data.find('PUT')==0:
		rdata=hdata(data)
		newconn.hfile.write(rdata)
	else:
		partial=re.search('Range: bytes=(.+?)-',data) # HTTP 1.1 Allows Partial Content and Range Requests
		if partial:
			newconn.frange=partial.group(1)
	newconn.nextseq=ack # Remember that this Ack is the last server side TCP sequence number
	hsession.append(newconn)

def hresponse(seq,data):
	for i in range(0,len(hsession)):
		#print  "%d e %d"%(hsession[i].nextseq, seq)
		if hsession[i].nextseq == seq:
			print "MATCHING!!!!"
			rdata=hdata(data)
			if rdata:
				if '206 (Partial Content)' in data: # Server accepts Partial Content
					hsession[i].hfile.seek(hsession[i].frange)
					hsession[i].frange+=len(rdata)
				hsession[i].hfile.write(rdata)
			hsession[i].nextseq+=len(data) # Found HTTP Data or not, the next TCP seq from server side is always increased by TCP data length

#Packet Analyser 
def pkgan(pkt):
	global dseq
	if not(TCP in pkt): # forcing check as tcp in filter isn't enough, for some reason....  
		return
	raw= pkt[TCP].payload
	data = str(raw)
	if not('HTTP' in data):
		return
	header=data.splitlines()[0]
	rsqt=['OPTIONS','GET','HEAD','POST','PUT','DELETE','TRACE','CONNECT'] # only GET, HEAD and PUT can be used to transfer files
																																				# the others request parameters is there only for algorithm correctness
	#print raw
	if any(x in header for x in rsqt): # Search for HTTP requests
		hrequest( pkt[IP].src,pkt[IP].dst,pkt[TCP].ack,data)
		#print "Req  %s %d"%(pkt[IP].src,pkt[TCP].ack)

	elif header.find('HTTP/')==0:  # Search for HTTP responses
		#print "Req  %d"%(pkt[TCP].seq)
		hresponse(pkt[TCP].seq,data)



def main2():
	if len(sys.argv) < 2:
		print "[*] Usage:", sys.argv[0] ," somefile.pcap"
		sys.exit(0)

	fpcap=sys.argv[1]
	print fpcap
	global hsession
	hsession=[]
	try:
		print "[*] Reading Pcap"
# Filtering tcp packages, with source on client and destination on server
		sniff(filter='tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)',prn=pkgan,offline=fpcap)
	except Exception, e:
		print "[!] ERROR: %s" % e
	finally:
		print "[*] Ending"
		for i in range(0,len(hsession)):
			hsession[i].hfile.close()

		sys.exit(0)

main2()

