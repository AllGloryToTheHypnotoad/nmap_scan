# Nmap Scan

Simple program to scan your LAN, identify hosts that are up and what ports are open on them. This info is then stored in [mongodb](http://www.mongodb.org) database.

## Setup

For OSX use `brew` to install mongodb:

    brew update
    brew install mongodb

Then use pip to get the python extensions:

    pip install pymongo

## Usage

You will need to run this as root using `sudo`. Unfortunately you have to be root to get the MAC addresses. Since IP addresses can change with DHCP, only the MAC addresses are constant and they are used to identify a host computer (or smart phone, play station, etc).

### Python

    sudo ./scan_network

### MongoDB

Make sure you start the db server with:

     mongod --dbpath db

This will allow you to connect to it. 

You can track clients from the command line tool `mongo`. Now list the databases and select one for use.

	> show dbs
	admin    (empty)
	local    0.078GB
	network  0.078GB
	test     (empty)
	> use network
	switched to db network
	> db.network.find().count()
	11
	>

How many machines found to date:
    
    db.network.find().count()
    
Search for a particular machine using its MAC address (**Note:** there should only be one listing, if there is more, then something got messed up):
    
    db.network.find({"addresses" : { "mac" : "40:30:04:F0:8C:5A"}})

List all machines found:
    
    db.network.find()

Delete all records and start over:
    
    db.network.remove('')

Insert a new record `host`.

    db.network.insert( host )

## To Do

* can't seem to get the computer names, nmap doesn't know them and bonjour seems useless. Avahi under linux has a command line tool to convert IP's into hostnames.


