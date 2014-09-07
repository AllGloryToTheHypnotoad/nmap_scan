#!/usr/bin/env python

import nmap
import optparse

def printPorts(ports):
	for p in ports:
		print " - "+str(p)+"/"+ports[p]['name']+" is "+ports[p]['state']
	

def printHost(h):
	print h['hostname'] + " is " + h['status']['state']
	print "-----------------------------------------"
	printPorts(h['tcp'])
	print "\n"

def nmapScan(network):
	nmScan = nmap.PortScanner()
#	nmScan.scan(network + "/24")
	nmScan.scan(network)
	hosts = nmScan.all_hosts()
	
	for h in hosts:
		printHost(nmScan[h])
	
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

