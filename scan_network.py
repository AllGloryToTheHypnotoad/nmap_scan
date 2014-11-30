#!/usr/bin/env python
#
# Kevin J. Walchko
# created: 7 Sept 2014
#

import nmap
#import optparse
from multiprocessing import Process
import multiprocessing
import socket
from awake import wol
import pymongo
import pprint
import datetime
import time
import logging
import re
import uuid

"""
{
	"_id" : ObjectId("540ceb098fc886adbd2a336c"),
	"status" : {
		"state" : "up",
		"reason" : "arp-response"
	},
	"vendor" : {
		"90:B9:31:EC:AA:46" : "Apple"
	},
	"ip" : "192.168.1.9",
	"hostname" : "",
	"tcp" : {
		"62078" : {
			"product" : "",
			"state" : "open",
			"version" : "",
			"name" : "iphone-sync",
			"conf" : "3",
			"extrainfo" : "",
			"reason" : "syn-ack",
			"cpe" : ""
		}
	},
	"mac" : "90:B9:31:EC:AA:46",
	"lastseen" : ISODate("2014-09-07T17:32:25.380Z")
}

"""
class DataBase:
	def __init__(self,db_name,srvr='localhost',port=27017):
		client = pymongo.MongoClient(srvr, port)
		self.db = client[db_name]
	
	"""
	Determine if a document already exists
	in: db and query_doc
	out: boolean
	"""
	def exist(self,doc):
		num = self.db.network.find( doc ).count()
		ans = False
		if num > 0: ans = True
		return ans
	
	def insert(self,doc):
		print 'insert'
		#self.db.network.insert(doc)
	
	def find(self,doc):
		return self.db.network.find_one(doc)
	
	"""
	Return all hosts
	in: none
	out: dict of everything
	"""
	def getAll(self):
		return self.db.network.find()
		
	"""
	Search db for MAC address
	in: db and query_doc
	out: boolean and MAC address
	"""
	def getMAC(self,doc):
		rec = self.db.network.find_one( doc )
		if not rec:
			return False,0
		return True, rec['mac']

class IP:
	def __init__(self):
		self.mac = self.getHostMAC()
		self.network = self.getNetwork()
		self.ip = self.getHostIP()
		
	"""
	 Only need the first 3 parts of the IP address
	 TODO: change name, sucks!
	"""
	def getNetwork(self):
		ip = socket.gethostbyname(socket.gethostname())
		i=ip.split('.')
		ip = i[0]+'.'+i[1]+'.'+i[2]+'.'
		return ip

	"""
	Need to get the localhost IP address 
	in: none
	out: returns the host machine's IP address
	"""
	def getHostIP(self):
		ip = socket.gethostbyname(socket.gethostname())
		return ip

	"""
	Major flaw doesn't allow you to get the localhost's MAC address
	in: none
	out: string of hex for MAC address 'aa:bb:11:22..'
	"""
	def getHostMAC(self):
		return  ':'.join(re.findall('..', '%012x' % uuid.getnode()))



class Nmap:
	def __init__(self):
		self.db = DataBase('network')
		self.ip = IP()
		
		#logging.basicConfig(level=logging.INFO)
		self.log = logging.getLogger('nmapScan')
	
	"""
	Runs the scan on a host ip and inserts it into mongodb
	in: host_ip and db
	out: none
	"""
	def nmapScan(self,host):
		p = multiprocessing.current_process()
		nm = nmap.PortScanner()
		scan = nm.scan(host)
		
		self.log.debug('Scan results: %s'%(scan))
		
		# grab the computer host info
		hosts = scan['scan']
		
		# no host at this ip address
		if not hosts:
			#self.log.info('[-] %s is DOWN, shutting down process %d'%(p.name,p.pid))
			return
		
		self.log.debug('Hosts file: %s'%(hosts))
		
		for key, h in hosts.iteritems():
			self.log.info('[+] %s is UP, in process %d'%(key,p.pid))
		
			# need to the MAC address
			if 'mac' not in h['addresses']:
				if self.ip.ip == key:
					#self.log.error("[-] can't grab MAC of localhost -- FIXME!!")
					self.log.info("[*] can't grab MAC of localhost -- fixing manually")
					mac = self.ip.mac
					h['addresses']['mac'] = mac
				else:
					self.log.error('[-] Could not get MAC for %s'%(key))
					return
		
			# nmap stores the ip and mac addr in addresses, this makes 
			# searching hard, so I pull them out	
			search_key = {'mac' : h['addresses']['mac'] }
			
			if not self.db.exist( search_key ):
				comp = self.formatDoc(h)
				comp['firstseen'] = datetime.datetime.now().strftime('%Y%m%d-%H:%M')
				#print 'insert'	
				comp['lastseen'] = datetime.datetime.now().strftime('%Y%m%d-%H:%M')	
				self.db.insert(comp)
				
	"""
	Run through db and attempt to wake all previously known hosts
	in: none
	out: none
	"""
	def wakeAllComputers(self):
		all = self.db.getAll()
		
		if all.count() == 0:
			self.log.info('[*] Database empty')
			return
		
		self.log.info('[*] Waking known computers:')
		for h in all:
			mac = h['mac']
			wol.send_magic_packet(mac)
			self.log.info('  > %s / %s'%(mac,h['ip']))
		self.log.info('----------------------------')
	
	def printNetwork(self):
		print 'hi'
		#hosts = self.db.search({
		
	"""
	Scan a network to detect hosts
	in: start/stop of network
	out: none
	"""
	def scanRange(self,start=1,stop=255):
		ip = self.ip.network
			
		self.log.info('---------- [Start] -----------')
		self.log.info(datetime.datetime.now())
		
		try:
			self.wakeAllComputers()
			jobs=[]
			for i in range(start,stop):
				host = ip + str(i)				
				#ret,mac = self.db.getMAC({'ip': host} )
				#if ret:
				#	wol.send_magic_packet(mac)
				#	self.log.info('[*] Wake %s / %s'%(mac,host))
				p = Process(target=self.nmapScan, args=(host,)) 
				jobs.append(p)
				p.start()
		except Exception, e:
			print e
	
	"""
	Given the output from nmap, turn it into a dict for mongo. Note, have to convert keys
	to strings (e.g., port numbers)
	in: nmap host info
	out: dict
	"""
	def formatDoc(self,h):
		comp = {
			'mac' : h['addresses']['mac'],
			'ip' : h['addresses']['ipv4'],
			#'hostname' : h['hostname'], 
			#'status' : h['status']['state']
		}
	
		# need to convert port numbers to strings for mongodb
# 		if 'tcp' in h:
# 			tcp = {}
# 			for k,v in h['tcp'].iteritems():
# 				if v['product'] == '':
# 					tcp[str(k)] = v['name'] 
# 				else:
# 					tcp[str(k)] = v['product'] 
# 			comp['tcp'] = tcp
		print comp
		return comp


"""
TODO: 
- need to enable SSL connection to mongodb
- need to get hostnames
"""
def main():
	# setup logger that processes will attach too
	logging.basicConfig(level=logging.INFO)
	log = logging.getLogger('nmapScan')
	
	# create file handler
 	fh = logging.FileHandler('nmapScan.log')
 	fh.setLevel(logging.WARNING)
 	
	# create formatter
 	fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
 	fh.setFormatter(fmt)
 	log.addHandler(fh)
 	
 	scan = Nmap()
	
	try:
		while True:
			scan.scanRange(1,200)
			time.sleep(5*60)
			
	except KeyboardInterrupt:
		print 'bye ...'

if __name__ == '__main__':
    main()

