#!/usr/bin/python
#TODO:
#Fix the scapy three way 
#Allow you to set an interface / adjust to scapy
#Add a loop to allow for 'relaunching'

from scapy.all import *
import os, pycurl, linecache, re, urllib2, socket, fcntl, struct, time, StringIO

dictionaryFile = 'dict.txt' #dictionary file
iface = 'eth0' #perfered interface
sourcePort = '666'
searchEngine = "http://www.hotbot.com/search/web?q=" #easy to work search engine
conf.verb = 0 # make scapy shut the hell up

def get_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,  # SIOCGIFADDR
		struct.pack('256s', ifname[:15])
	)[20:24])

def get_srcip():
	ifaceIP = get_ip_address(iface)
	userSrcip = raw_input("Enter source IP: ["+ ifaceIP +"] ")
	if not userSrcip:
		srcip = ifaceIP
	else: 
		srcip = userSrcip
	return srcip

def get_dict():
	userDict = raw_input("Enter the dictionary path: ["+ dictionaryFile +"] ")
	if not userDict:
		dictFile = dictionaryFile
	else: 
		dictFile = userDict
	return dictFile 

def get_sport():
	userSport = raw_input("Enter the dictionary path: ["+ sourcePort +"] ")
	if not userSport:
		sport = sourcePort
	else: 
		sport = userSport
	return int(sport)

def get_url_count():
	userUrls = raw_input("How many URLs do you want want? [1] ")
	if not userUrls:
		url_count = 1
	else: 
		url_count = userUrls
	return int(url_count)	

def get_dances():
	userDance = raw_input("\nLast but not least, how many times are we doing this dance? [1] ")
	if not userDance:
		dance_count = 1
	else: 
		dance_count = userDance
	return int(dance_count)	

def get_loops():
	userLoops = raw_input("\nDid you want to run this once, or loop it some? Enter loops: [1] ")
	if not userLoops:
		loops_count = 1
	else: 
		loops_count = userLoops
	return int(loops_count)		

def get_urls(count):
	urls = 1
	urlCount = 0
	results = set()

	if count > 100:
		print str(count) +"!?!? You're a MAD MAN, I have to throttle this . . . sorry."

	while urlCount < count:

		if count > 100:
			time.sleep(3)

		dictLine = linecache.getline('dict.txt', urls)
		#print 'Fetching:', searchEngine + dictLine

		req = urllib2.Request(searchEngine + dictLine)
		resp = urllib2.urlopen(req)
		data = resp.read()

		if resp.headers.get('content-encoding', '') == 'gzip':
			data = StringIO.StringIO(data)
			gzipper = gzip.GzipFile(fileobj=data)
			html = gzipper.read()
		else:
			html = data

		results |= set(re.findall(r'www\.[^.]{2,}\.com', html))

		urls = urls + 1
		urlCount = len(results)
		print urlCount, "of", count

	if urlCount > count:
		print "\nParsed",urlCount,"URLs. The last", urlCount - count, "will be dropped."
	
		while urlCount > count:
			results.pop()
			urlCount = len(results)

	return results

def resolve_ips(domains):
	domain_to_ip = {}

	for domain in domains:

		domainIP = socket.gethostbyname_ex(domain)
		domain_to_ip[domainIP[2][0]] = domain
	
	return domain_to_ip

def set_iptables(domain_to_ip, srcip):

	for dstip, domain in domain_to_ip.iteritems():

		os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -s "+srcip+" -d "+dstip+" --dport 80 -j DROP")
		os.system("iptables -A OUTPUT -s "+srcip+" -d "+dstip+" -p ICMP --icmp-type port-unreachable -j DROP")

def send_synpacket(domain_to_ip, srcip, sp, i):
	
	for dstip, domain in domain_to_ip.iteritems():
		
		spI = int(sp + i)

		ip=IP(src=srcip, dst=dstip)
		TCP_SYN=TCP(sport=spI, dport=80, flags="S", seq=100)
		send(ip/TCP_SYN)

def send_packet(domain_to_ip, srcip, sp):
	
	for dstip, domain in domain_to_ip.iteritems():

		ip=IP(src=srcip, dst=dstip)
		TCP_SYN=TCP(sport=sp, dport=80, flags="S", seq=100)
		TCP_SYNACK=sr1(ip/TCP_SYN)

		my_ack = TCP_SYNACK.seq + 1
		TCP_ACK=TCP(sport=sp, dport=80, flags="A", seq=101, ack=my_ack)
		send(ip/TCP_ACK)

		my_payload="GET / HTTP/1.0\r\nHost: "+domain+"\r\n"
		TCP_PUSH=TCP(sport=sp, dport=80, flags="PA", seq=102, ack=my_ack)
		send(ip/TCP_PUSH/my_payload)

def niceExit():
	print "\nThe script has finished, however it's going to sleep for a bit while the server continues to comunicate."
	print "If you want, you can CTRL+C out -- just remember you will need to run:"
	print "iptables --flush OUTPUT to clear your iptables."
	time.sleep(60)
	os.system("iptables --flush OUTPUT")
	exit()




def main():
	os.system('clear')
	print "      __           __             __  ___  ___  __  \n|  | |__) |       |__) |     /\  /__`  |  |__  |__) \n\__/ |  \ |___    |__) |___ /~~\ .__/  |  |___ |  \ \n\n"
	print "This srcipt contains *NO* error checkings, your on your own...don't slip!"
	print "ALSO -- use sudo...\n"

	srcip = get_srcip()
	sport = get_sport()
	dictFile = get_dict()

	userUrls = get_url_count()
	urls = get_urls(int(userUrls))
	countUrls = len(urls)
	print "\n"+str(countUrls), " grabbed."

	print "\nResolving DNS for IP address..."
	domainsIps = resolve_ips(urls)

	print "\nSetting iptables rules ... (these will be cleared when the script finishes)"
	set_iptables(domainsIps, srcip)

	print "\nEverything *should* be ready... "
	userSend = raw_input("Type 'SYN' to send SYNs only or '3' to send full 3-way: ")
	
	danceCount = get_dances()
	loopCount = get_loops()

	if userSend == 'SYN' or userSend == 'syn': 
		print 'FIRING SYN!'
		for i in range (loopCount):
			for i in range (danceCount): 
				send_synpacket(domainsIps, srcip, sport,i)
		niceExit()
	if userSend == '3': 
		print 'FIRING THE THREE WAY!'
		send_synpacket(domainsIps, srcip, sport)
		niceExit()		
	else:
		print "Something else was pressed, exiting ..."
		niceExit()
 



if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    pass