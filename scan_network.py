#!/usr/bin/env python

import nmap
#import optparse
from multiprocessing import Process
import multiprocessing
import socket
#from awake import wol
import pymongo
import pprint
import datetime
import logging
	
"""
Determine if a document already exists
in: db and query_doc
out: boolean
"""
def exist(db,doc):
	num = db.network.find( doc ).count()
	ans = False
	if num > 0: ans = True
	return ans

# def printHost(h,ip):
# 	print h['hostname'] + " is " + h['status']['state']
# 	print "-["+ip+"]------------------------"
# 	ports = h['tcp'] #printPorts(h['tcp'])
# 	pp = sorted(ports.iterkeys())
# 	for p in pp:
# 		print " - "+str(p)+"/"+ports[p]['name']+" is "+ports[p]['state']
# 	print "\n"

"""
in: nmap host info
out: dict
"""
def formatDoc(h):
	comp = {
		'mac' : h['addresses']['mac'],
		'ip' : h['addresses']['ipv4'],
		'hostname' : h['hostname'], 
		'status' : h['status'],
		'vendor' : h['vendor']
	}
	
	# need to convert port numbers to strings for mongodb
	if 'tcp' in h:
		tcp = {}
		for k,v in h['tcp'].iteritems():
			tcp[str(k)] = v 
		comp['tcp'] = tcp
# 		print 'tcp -----------'
# 		pprint.pprint(comp['tcp'])
# 		print 'h[tcp] -----------'
# 		pprint.pprint(h['tcp'])
	return comp

"""
Runs the scan on a host ip and inserts it into mongodb
in: host_ip and db
out: none
"""
def nmapScan(host,db):
	log = logging.getLogger('nmapScan')
	log.setLevel(logging.INFO)
	
	# create file handler
 	fh = logging.FileHandler('nmapScan.log')
 	fh.setLevel(logging.WARNING)
	# create formatter
 	fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
 	fh.setFormatter(fmt)
 	log.addHandler(fh)
	
	p = multiprocessing.current_process()
	#print " Starting Scan ", p.name, p.pid
	nm = nmap.PortScanner()
	#scan = nm.scan(host,'22-443')
	scan = nm.scan(host)
	
	#print'scan'
	#pprint.pprint(scan)
	
	# grab the computer host info
	hosts = scan['scan']
	
	# no host at this ip address
	if not hosts:
		log.info('[-] %s is down, shutting down process %d'%(p.name,p.pid))
		#print p.name, 'is down, shutting down process',p.pid
		return
	
	#print 'hosts -------------'
	#pprint.pprint(hosts)
	for key, h in hosts.iteritems():
		log.info('[+] %s is up, in process %d'%(key,p.pid))
		#pprint.pprint(h)
		
		
		if 'mac' not in h['addresses']:
			print '[-] ERROR: Need to run as root'
			print 'is this localhost:',getLocalIP()==host
			exit()
		
		# nmap stores the ip and mac addr in addresses, this makes 
		# searching hard, so I pull them out	
		search_key = {'mac' : h['addresses']['mac'] }
		if exist(db,search_key):
# 			db.network.update(
# 				search_key,
# 				{'$set' : {'lastseen': datetime.datetime.now()}}
# 				)
			db.network.remove(search_key)
#		else:
		comp = formatDoc(h)
		comp['lastseen'] = datetime.datetime.now()
		db.network.insert(comp)
	
	#printHost(nm[host],p.name)
	

# Only need the first 3 parts of the IP address
# TODO: change name, sucks!
def getIP():
	ip = socket.gethostbyname(socket.gethostname())
	i=ip.split('.')
	ip = i[0]+'.'+i[1]+'.'+i[2]+'.'
	return ip

"""
in: none
out: returns the host machine's IP address
"""
def getLocalIP():
	ip = socket.gethostbyname(socket.gethostname())
	return ip

"""
TODO: 
- need to put in a loop
- need to enable SSL connection to mongodb
- need to handle error of local machine mac address can't get
- need to get hostnames
"""
def main():
	# setup db
	client = pymongo.MongoClient('localhost', 27017)
	db = client['network']
	
	ip = getIP()
	
	try:
		jobs=[]
		for i in range(1,20):
			host = ip + str(i)
			#wol.send_magic_packet(host)
			p = Process(name=host,target=nmapScan, args=(host,db)) 
			jobs.append(p)
			p.start()
			
	except KeyboardInterrupt:
		print 'bye ...'

if __name__ == '__main__':
    main()

