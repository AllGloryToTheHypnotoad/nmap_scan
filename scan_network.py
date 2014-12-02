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
#import pymongo
import pprint as pp
import datetime
import time
import logging
import re
import uuid

import yaml

class YamlDoc:	
	def read(self,filename):
		# need better testing, breaks if file missing
		try:
			f = open(filename,'r')
			file = yaml.safe_load(f)
			f.close()
		except IOError:
			file = dict()
			print 'ioerror'
		return file
		
	def write(self,filename,data):
		f = open(filename,'w')
		yaml.safe_dump(data,f)
		f.close()
		


"""
DEBUG:nmapScan:Hosts file: {u'192.168.1.17': {'status': {'state': u'up', 'reason': u'arp-response'}, 'hostname': '', 'vendor': {u'B8:27:EB:0A:5A:17': u'Raspberry Pi Foundation'}, 'addresses': {u'mac': u'B8:27:EB:0A:5A:17', u'ipv4': u'192.168.1.17'}, u'tcp': {548: {'product': u'Netatalk', 'state': u'open', 'version': u'2.2.2', 'name': u'afp', 'conf': u'10', 'extrainfo': u'name: calculon; protocol 3.3', 'reason': u'syn-ack', 'cpe': u'cpe:/a:netatalk:netatalk:2.2.2'}, 22: {'product': u'OpenSSH', 'state': u'open', 'version': u'6.0p1 Debian 4+deb7u2', 'name': u'ssh', 'conf': u'10', 'extrainfo': u'protocol 2.0', 'reason': u'syn-ack', 'cpe': u'cpe:/o:linux:linux_kernel'}}}}
DEBUG:nmapScan:Hosts file: {u'192.168.1.15': {'status': {'state': u'up', 'reason': u'arp-response'}, 'hostname': '', 'vendor': {u'28:0D:FC:41:24:44': u'Sony Computer Entertainment'}, 'addresses': {u'mac': u'28:0D:FC:41:24:44', u'ipv4': u'192.168.1.15'}}}

change DataBase to a dict due to the small number of computers on local network.

{
	"90:B9:31:EC:AA:46": {
		"vendor": "Apple",
		"ip": "123.122.1.1",
		"hostname": "billy-bob",
		"tcp": { "123": "something", ... },
		"lastseen" : "12 aug 2012"
	}
}
"""
class DataBase:
	def __init__(self,filename):
		y = YamlDoc()
		self.db = y.read(filename)
		if (self.db) != dict:
			self.db = dict()
		self.filename = filename
	
	"""
	Determine if a document already exists
	in: db and query_doc
	out: boolean
	"""
	def exist(self,mac):
		ans = mac in self.db
		return ans
	
	def insert(self,dic):
		self.db.update(dic)
	
	def find(self,doc):
		return self.db[doc]
	
	"""
	Return all hosts
	in: none
	out: dict of everything
	"""
	def getAll(self):
		return self.db
		
	def save(self,filename):
		y = YamlDoc()
		y.write( filename, self.db )

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
	
	"""
	Gets all of the network info
	in: none
	out: dict with ip, mac, and network info
	"""
	def getAll(self):
		ans = {'ip': self.ip, 'mac': self.mac, 'network': self.network }
		return ans



class Nmap:
	def __init__(self):
		self.db = DataBase('hosts.yaml')
		self.ip = IP()
		self.net = IP().getAll()
		
		#logging.basicConfig(level=logging.INFO)
		self.log = logging.getLogger('nmapScan')
	
	"""
	Runs the scan on a host ip and inserts it into mongodb
	in: host_ip and db
	out: none
	"""
	def nmapScan(self,host):
		#p = multiprocessing.current_process()
		nm = nmap.PortScanner()
		
		# http://nmap.org/book/man-briefoptions.html
		# -sS TCP SYN
		# -O OS detection
		# -F faster scan mode, fewer ports searched 
		scan = nm.scan(host,arguments=' -sS -O -F')
		
		# grab the computer host info
		hosts = scan['scan']
		
		# no host at this ip address
		if not hosts:
			#self.log.info('[-] %s is DOWN, shutting down process %d'%(p.name,p.pid))
			return
		
		for key, h in hosts.iteritems():
			#self.log.info('[+] %s is UP, in process %d'%(key,p.pid))
			
			# need to get the MAC address
			if 'mac' not in h['addresses']:
				if self.ip.ip == key:
					self.log.info("[*] can't grab MAC of localhost -- fixing manually")
					mac = self.ip.mac
					h['addresses']['mac'] = mac
				else:
					self.log.error('[-] Could not get MAC for %s'%(key))
					return
			
			# nmap stores the ip and mac addr in addresses, this makes 
			# searching hard, so I pull them out	
			search_key = str(h['addresses']['mac'])			
			comp = self.formatDoc(h)
			
			if self.db.exist( search_key ):
				comp[search_key]['lastseen'] = str(datetime.datetime.now().strftime('%Y%m%d-%H:%M'))
			else:
				comp[search_key]['firstseen'] = str(datetime.datetime.now().strftime('%Y%m%d-%H:%M'))
				#print 'insert'	
				comp[search_key]['lastseen'] = str(datetime.datetime.now().strftime('%Y%m%d-%H:%M'))
				print '------- comp -------------'
				print comp
				#exit()
				
			self.db.insert(comp)
				
				
	"""
	Run through db and attempt to wake all previously known hosts
	in: none
	out: none
	"""
	def wakeAllComputers(self):
		all = self.db.getAll()
		
		if len(all) == 0:
			self.log.info('[*] Database empty')
			return
		
		self.log.info('[*] Waking known computers:')
		for mac in all.keys():
			#wol.send_magic_packet(mac)
			self.log.info('  > %s / %s'%(mac,all[mac]['ip']))
		self.log.info('----------------------------')
		
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
			#jobs=[]
			for i in range(start,stop):
				host = ip + str(i)			
				#p = Process(target=self.nmapScan, args=(host,)) 
				#jobs.append(p)
				#p.start()
				#p.join()
				self.log.info('Scanning: %s'%host)
				self.nmapScan(host)
			self.db.save('hosts.yaml')
		except Exception, e:
			print e
	
	"""
	Given the output from nmap, turn it into a dict for mongo. Note, have to convert keys
	to strings (e.g., port numbers)
	
	Hosts file: {u'192.168.1.15': {'status': {'state': u'up', 'reason': u'arp-response'}, 'hostname': '', 'vendor': {u'28:0D:FC:41:24:44': u'Sony Computer Entertainment'}, 'addresses': {u'mac': u'28:0D:FC:41:24:44', u'ipv4': u'192.168.1.15'}}}
	
	{
		"90:B9:31:EC:AA:46": {
			"vendor": "Apple",
			"ip": "123.122.1.1",
			"hostname": "billy-bob",
			"tcp": { "123": "something", ... },
			"lastseen" : "12 aug 2012"
		}
	}
	
	in: nmap host info
	out: dict
	"""
	def formatDoc(self,h):
		print 'formatDoc --------------'
		pp.pprint(h)
		comp = {
			h['addresses']['mac']: {
				'vendor':    h['vendor'].values(),
				'ip' :       h['addresses']['ipv4'],
				'hostname' : h['hostname'], 
				'status' :   h['status']['state']
			}
		}
		
		# need to convert port numbers to strings for mongodb
		if 'tcp' in h:
			tcp = {}
			for k,v in h['tcp'].iteritems():
				if v['product'] == '':
					tcp[str(k)] = v['name'] 
				else:
					tcp[str(k)] = v['product'] 
			comp[h['addresses']['mac']]['tcp'] = tcp
		return comp


"""
TODO: 
- need to enable SSL connection to mongodb
- need to get hostnames
"""
def main():
	# setup logger that processes will attach too
	logging.basicConfig(level=logging.DEBUG)
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
			scan.scanRange(1,29)
			time.sleep(5)
			
	except KeyboardInterrupt:
		print 'bye ...'

if __name__ == '__main__':
    main()

