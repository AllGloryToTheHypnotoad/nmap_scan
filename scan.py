#!/usr/bin/env python

import nmap
import optparse
impport logging

def printPorts(ports):
	for p in ports:
		print " - "+str(p)+"/"+ports[p]['name']+" is "+ports[p]['state']
	

def printHost(h):
	print h['hostname'] + " is " + h['status']['state']
	print "-----------------------------------------"
	printPorts(h['tcp'])
	print "\n"

def nmapScan(host,db):
	#logging.basicConfig(level=logging.INFO)
	log = logging.getLogger('nmapScan')
	
	p = multiprocessing.current_process()
	nm = nmap.PortScanner()
	#scan = nm.scan(host,'22-443')
	scan = nm.scan(host)
	
	log.debug('Scan results: %s'%(scan))
	
	# grab the computer host info
	hosts = scan['scan']
	
	# no host at this ip address
	if not hosts:
		log.info('[-] %s is DOWN, shutting down process %d'%(p.name,p.pid))
		return
	
	
	log.debug('Hosts file: %s'%(hosts))
	
	for key, h in hosts.iteritems():
		log.info('[+] %s is UP, in process %d'%(key,p.pid))
		
		# need to the MAC address
		if 'mac' not in h['addresses']:
			if getLocalIP() == host:
				#log.error("[-] can't grab MAC of localhost -- FIXME!!")
				log.info("[*] can't grab MAC of localhost -- fixing manually")
				mac = getLocalMAC()
				h['addresses']['mac'] = mac
			else:
				log.error('[-] ERROR: Need to run this program as root')
				return
		
		# nmap stores the ip and mac addr in addresses, this makes 
		# searching hard, so I pull them out	
		search_key = {'mac' : h['addresses']['mac'] }
		
		if exist(db,search_key):
# 			db.network.update(
# 				search_key,
# 				{'$set' : {'lastseen': datetime.datetime.now()}}
# 				)
			db.network.remove(search_key)
		
		comp = formatDoc(h)
		comp['lastseen'] = datetime.datetime.now()
		db.network.insert(comp)
	
def main():
	parser = optparse.OptionParser('usage %prog '+ '-t <target host>')
	parser.add_option('-t', dest='tgtHost', type='string', help='specify target host')
	(options, args) = parser.parse_args()

	tgtHost = options.tgtHost

	if (tgtHost == None):
		nmapScan('127.0.0.1')
	
	else:
		nmapScan(tgtHost)
	
	#nmapScan('192.168.1.1')
#	nmapScan('192.168.1.4')
#	nmapScan('127.0.0.1')



if __name__ == '__main__':
    main()

