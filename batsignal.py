#!/usr/bin/python

from scapy.all import *
import threading
import time
import curses

hostlist={}
thescreen=curses.initscr()

def printtopten():
    a="Unique hosts per domain\n"
    a=a+"-----------------------\n"
    for k in sorted(hostlist,key=lambda k: len(hostlist[k]), reverse=True):
        a=a+"%s: %s\n" %(k,len(hostlist[k]))
    thescreen.addstr(0,0,a)
    thescreen.refresh()

def analyze(packet):
    #print packet.summary()
    if (packet.getlayer("DNS").qr==0):
        #packet is a query
        hostname=(packet[DNSQR].qname)
        domainsplit=(packet[DNSQR].qname).split(".")[-3:]
        domain=domainsplit[0]+"."+domainsplit[1]
        #print domain.lower()
        #Check to see if a dictionary entry for this domain exists
        if not domain in hostlist:
            #print "domain not in dictionary"
            hostlist[domain]=[hostname]
        else:
            #print "domain in dictionary"
            #Check to see if hostname is in the dictionary entry
            if not hostname in hostlist[domain]:
                #print "host not in domain entry"
                hostlist[domain].append(hostname)

def sniffit():
    sniff(iface="eth0",filter="udp port 53",prn=analyze)

sniffer=threading.Thread(target=sniffit)
sniffer.daemon=True
sniffer.start()


while True:
    time.sleep(10)
    printtopten()
