#!/usr/bin/python -O
# Simple HTTP Dissector tool developed as an exercise  
# Author: Otavio Augusto otavioarj$at$gmail.com
# At Public Domain if, and only if, the author remain unchanged or a clear reference is made to him =]
# This code completely depends on Scapy http://www.secdev.org/projects/scapy 
from __future__ import print_function
import sys, logging, re, time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# HTTP Stream class, used to store: File transfer obj,last TCP.seq + inclement and file range
#  File transfered can be either a HTTP Body or structured file, like ones formated as JPG, PE32, etc. 
#  Last TCP seq is actually last know server side TCP seq incremented by (several) server transfered data.
#  File range is the pointer where to start writing the file, as HTTP can define ranges from start/end of transmission to files
class hstream:
	hfile=''
	nextseq=0
	frange=0

#HTTP Data Parser
def hdata(data):
	rdata=data.split('\r\n\r\n',1) # Split HTTP Header from Data
	#print rdata[1]
	if len(rdata)>1:
		return rdata[1]
	else:
		return ' '


#HTTP Request Handler
def hrequest (src,dst,ack,data):
	hparse=re.search('/(.+?) HTTP/1.1', data)	
	if hparse:
		fname=hparse.group(1).split('/') # Split some /path/path2/file into [path, path2, file]
		fname=fname[len(fname)-1]        #   and get the last one to be file name
	else:
		hparse=re.search(' ^/(.+?) HTTP', data) # In the case where no path is given
		if not hparse:
			fname='none'	# Last resource, where no path or file name can be found
		else:
			fname=hparse.group(1)
	fname=fname.split('?',1)[0]
	fname=fname.split('&',1)[0]
	newconn=hstream()
	newconn.hfile= open(str(src)+"-"+str(dst)+"."+str(fname), "a")
	if data.find('PUT')==0:  # For PUT, the file is write at request time
		rdata=hdata(data)
		newconn.hfile.write(rdata)
	else:
		partial=re.search('Range: bytes=(.+?)-',data) # HTTP 1.1 Allows Partial Content and Range Requests
		if partial:
			newconn.frange=partial.group(1) # Store the start of range, to write file according to it
	newconn.nextseq=ack # Remember that this Ack is the last server side TCP sequence number
	hsession.append(newconn)
	print(debug,"\r[+] HTTP Request: ",ack," appended ",end='\r')


#HTTP Response Handler
def hresponse(seq,data,isresp):
	for i in reversed(range(0,len(hsession))):  # Iterate from tail to head, to always match last equal TCP seq, as HTTP can reuse the same TCP conn
		#print  "%d e %d"%(hsession[i].nextseq, seq)
		if hsession[i].nextseq == seq:
			if isresp:  # True if this HTTP Response contain a HTTP Header
				rdata=hdata(data)
				if rdata:
					if '206 (Partial Content)' in data: # Server accepts Partial Content
						hsession[i].hfile.seek(hsession[i].frange)
						hsession[i].frange+=len(rdata)
					hsession[i].hfile.write(rdata)
			else:
				hsession[i].hfile.write(data)
			hsession[i].nextseq+=len(data) # Found HTTP Data or not, the next TCP seq from server side is always increased by TCP data length
			print("[+] HTTP Response:",seq,"found. Data length:",hsession[i].nextseq-seq,end='\r')


#Packet Analyser 
def pkgan(pkt):
	if not(TCP in pkt): # forcing check as tcp in filter isn't enough, for some reason....  
		return
	raw= pkt[TCP].payload
	data = str(raw)
	if 'HTTP' in data:
		header=data.splitlines()[0]
		rsqt=['OPTIONS','GET','HEAD','POST','PUT','DELETE','TRACE','CONNECT'] 
		if any(header.find(x)==0 for x in rsqt): # Search for HTTP requests
			hrequest( pkt[IP].src,pkt[IP].dst,pkt[TCP].ack,data)
		elif header.find('HTTP')==0: # It's a HTTP responses, as it have a HTTP Header, but not a request ones
			hresponse(pkt[TCP].seq,data,True)
	else: # It can be a HTTP response, that will be confirmed only if TCP seqs matches, as it may contain only file data with no HTTP Header
		hresponse(pkt[TCP].seq,data,False)

# MAIN
def main():
	if len(sys.argv) < 2:
		print ("[*] Usage:"+ sys.argv[0] +" somefile.cap [optional d for debug]")
		sys.exit(0)

	fpcap=sys.argv[1]
	global debug
	debug=''
	if len(sys.argv)>2:
		debug='\n'
	global hsession
	hsession=[]
	try:
		print ("[*] Capture file sniffing started")
# Filtering tcp packages from/to port 80 and where ACK/SYN flags isn't alone on TCP package. That minimize noises for HTTP parser
		sniff(filter='tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)',prn=pkgan,offline=fpcap)
	except Exception , e:
		print ("\n[!] ERROR: %s",e)
	finally:
		print ("\n[*] Ending")
		for i in range(0,len(hsession)):
			hsession[i].hfile.close()
		sys.exit(0)

main()

