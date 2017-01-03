#!/usr/bin/python

import requests         #libary to perform HTTP calls
import time             #time
import xml.etree.ElementTree as ET  #XML parser to analyze logs
import datetime
from datetime import date, timedelta

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""


def PortKnockedAction ():
	print ("Ports Knocked, ")
	###Section to include the action to do after the ports were knocked###


def WasThePortKnocked (LogAPI, PortSeqPlain):
	IPList = []	
	Ports = ""
	CommitResponse = requests.get(LogAPI)
	JobID= find_between( CommitResponse.text, "<job>", "</job>" )
	ShowJob = Url + '?type=log&action=get&job-id=' + JobID + APIkey
	PendingCommit = 1
	Portsknocked=False
	while (PendingCommit == 1):
	    #check commit status every 2 seconds
	    time.sleep(2)
	    CommitStatus = requests.get(ShowJob)
	    if find_between( CommitStatus.text, "<status>", "</status>" ) == 'FIN':             
	        PendingCommit = 0
	root = ET.fromstring(CommitStatus.text)  
	#Getting the IP addresses      
	for entry in root.findall("./result/log/logs/entry"):
		src = entry.find('src').text
		IPList.append(src)
	SrcIPList = list(set(IPList))   #Getting unique IP addresses to iterate over them
	for IP in SrcIPList:
		for entry in root.findall("./result/log/logs/entry"):
			if entry.find('src').text == IP:
				Ports = Ports + entry.find('dport').text + "-"
		print ("Debug:" + Ports +"\t" + PortSeqPlain)				
		if Ports== PortSeqPlain:	
			print ("Ports knocked from the source IP:" + IP )
			Portsknocked=True
			break 		#Ports Knocked breaking loop
		else:
			Ports = ""		
	return Portsknocked

#Variables defined per user needs
Url= 'https://firewall.com/api'
APIkey = '&key='
PortSeq = ["777","888","999"]
DstIP = "172.16.1.1"

#Building XML API calls
previoustime = datetime.datetime.now() - datetime.timedelta(minutes=1)
date = previoustime.strftime("%Y/%m/%d %X")
print (date)
CheckingPorts= "?type=log&log-type=traffic&query=((( addr.dst in 172.16.1.1 ) and ( receive_time geq '"+date+"' )) and (( port.dst eq "+PortSeq[0]+" ) or ( port.dst eq "+PortSeq[1]+" ) or ( port.dst eq "+PortSeq[2]+" )))"
LogAPI = Url + CheckingPorts + APIkey

#Executing script
PortSeqPlain = "-".join(reversed(PortSeq)) + "-"

try:
	while True:
		if WasThePortKnocked(LogAPI, PortSeqPlain):
			PortKnockedAction()
		else:
			print ("Ports not knocked, sleeping for 1 minute")
		time.sleep(60)	
except KeyboardInterrupt:
    print ("Good bye master")

