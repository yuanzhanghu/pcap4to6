#!/usr/bin/env python
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.layers.inet import TCP
from scapy.utils import rdpcap, wrpcap
import pdb, sys, os
import re, random

from scapy.all import *

ipDict = {};
def generateIpv6(baseIpv4=None):
    global ipDict;
    if (baseIpv4):
        if (not baseIpv4 in ipDict.keys()):
            ipDict[baseIpv4] = \
                "2001::13:23:" + str(random.randint(10, 99));
        return ipDict[baseIpv4];
    else:
        return "2001::12:23:" + str(random.randint(10, 99));

def header4to6 (ipheader):
    srcIP = ipheader.src;
    dstIP = ipheader.dst;
    proto = ipheader.proto;
    header6 = IPv6();
    header6.src = generateIpv6 (srcIP);
    header6.dst = generateIpv6 (dstIP);
    header6.proto = proto;
    return header6;

def payload4to6 (payload):
    before = len(payload);
    if (before > 0):
        srcStr = str(payload);
        newStr = re.sub(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
                        generateIpv6(),
                        srcStr, flags=re.MULTILINE);
        return newStr;
    return payload;

def convert4to6 (pkt):
    """ convert ipv4 to ipv6 pkt, including header and payload conversion. 
    """
    ether = Ether();
    ether.type = 0x86dd;
    ether.src = pkt.src;
    ether.dst = pkt.dst;
    header6 = header4to6 (pkt['IP']);

    if ('TCP' in pkt):
        l4type = 'TCP';
    elif ('UDP' in pkt):
        l4type = 'UDP';
    else:
        l4type = None;
    if (l4type == 'TCP' or l4type == 'UDP'):
        newpayload = payload4to6(pkt[l4type].payload);
        pkt[l4type].remove_payload();
        newpkt = ether /header6 / pkt[l4type] / newpayload;
        del pkt[l4type].chksum;
    else:
        newpkt = ether /header6 / pkt['IP'].payload;
    return newpkt;
    
if __name__ == "__main__":
    if (len(sys.argv) != 2):
        print "./pcap4to6.py <ipv4_pcap_file>";
        sys.exit(0);
    pkts = rdpcap (sys.argv[1]);
    newpkts = [];
    for pkt in pkts:
        newpkts.append (convert4to6 (pkt));
    wrpcap ("out.pcap", newpkts);
