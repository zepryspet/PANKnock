# PANKnock
PortKnocking log analysis on Palo Alto Firewalls

Pythonv3

This repository contains 2 scripts:
1. PANknock.py - Analayses a sequence of ports going to a destination IP (port knocking) to do something (User configured) for example to enable global Protect on an interface, create a security policy, send an email, etc. it uses the following parameters:

Url= 'https://firewall.com/api'		#Use your firewall IP or FQDN
APIkey = '&key=" 					#Use your XML Palo Alto API
PortSeq = ["777","888","999"]		#Port Knocking sequence 
DstIP = "172.16.1.1"				#Destination used to check the logs for port knocking, this can be your firewall IP or a host behind the firewall but the traffic must be logged.

The action must be configured in the function "def PortKnockedAction ()"

2.Port-knocking.py - Uses scapy to send TCP port knockings on the configured destination ports to the configured destination IP.
