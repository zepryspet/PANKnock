#! /usr/bin/env python

from scapy.all import *	#Importing scapy
import argparse         #Read CLI input
import time             #time

# VARIABLES
dst = "172.16.1.1"
sport = random.randint(1024,65535)
dports = [777,888,999]

for dport in dports:
	send(IP(dst=dst)/TCP(dport=dport))
	time.sleep(1)						#Wait for 1 seconds before sending the new syn