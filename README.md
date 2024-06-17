# Intrusion Detection System 
### SIF Accelerator Programme Project, with Sustainable Living Labs

An intrustion detection system (IDS) built with Python using the Scapy library. This IDS is able to detect 4 different DDoS attacks (SYN flood, UDP/ICMP flood, ARP spoofing, and DNS amplification) and a port scanning attack. The system logs out any attack that is detected on the computer onto a separate text file, which is compatible to be imported into table visualising softwares such as PowerBI.

## Installation

### Dependencies:
```
pip install scapy datetime time threading json
```

### Running the IDS script:
Windows:
```
git clone https://github.com/ponleou/Intrusion-Detection-System.git \
cd Intrusion-Detection-System \
python IDS.py
```

MacOS or Linux:
```
git clone https://github.com/ponleou/Intrusion-Detection-System.git \
cd Intrusion-Detection-System \
sudo python3 IDS.py
```

## IDS Modification
The IDS allows for adjustments to global variables to optimise detection sensitivity for different networks and devices such as:
- `SYNFLOOD_THRESHOLD`: the minimum number of unresponded SYN packets in the period of `MEMORY_RESET_TIME` to alert a SYN flood attack detection (higher means less sensitive).
- `UDPFLOOD_THRESHOLD`: the minimum number of ICMP packets in response to UDP packets in the period of `MEMORY_RESET_TIME` to alert a UDP flood attack detection (higher means less sensitive).
- `PORT_SCAN_THRESHOLD`: the minimum number of ports accessed by one device with SYN packets in the period of `MEMORY_RESET_TIME` to alert a port scanning attack detection (higher means less sensitive).
- `DNS_AMP_THRESHOLD`: the minimum number of DNS amplification packets in the period of `MEMORY_RESET_TIME` to alert a DNS amplification attack detection (higher means less sensitive)
- `DNS_REPLY_BYTE_THRESHOLD`: the minimum number of bytes a DNS response/reply packet to classify as a DNS amplification packet (higher means less sensitive).
- `TIME_CHECK`: the time in seconds to check the "detection system memories" for any detection that exceeds the thresholds. Once exceeded, a detection log will be outputted and the memory for that detection system will be cleared.
- `VERBOSE`: log levels
    - -1 for no logs
    - 0 for basic attack detection logs **(recommended)**
    - 1 for other networking logs (useful for monitoring and adjusting thresholds)

Other global variables that are adjustable, but not recommended:
- `ARP_SPOOF_THRESHOLD`: the minimum number of ARP spoofed packets in the period of `MEMORY_RESET_TIME` to alert a ARP spoofing attack detection (higher means less sensitive)
- `MEMORY_RESET_TIME`: the time in seconds to store packet information for "detection system memories" before clearing/resetting
- `CHECK_RESETTABLE`: the time in seconds to check if a detection system memory is clearable/resettable

## Attack simulations
Attack simulations include SYN flood, UDP flood, ARP spoofing, DNS amplification, and port scanning attacks that can be used on the device with the IDS to test for detection.
### SYN flood attack
Windows:
```
cd attack_and_simulation \
python synflood_simulation.py
```
MacOS or Linux:
```
cd attack_and_simulation \
sudo python3 synflood_simulation.py
```
### UDP flood attack
Windows:
```
cd attack_and_simulation \
python udpflood_simulation.py
```
MacOS or Linux:
```
cd attack_and_simulation \
sudo python3 udpflood_simulation.py
```
### Port scanning attack
Windows:
```
cd attack_and_simulation \
python portscan_simulation.py
```
MacOS or Linux:
```
cd attack_and_simulation \
sudo python3 portscan_simulation.py
```
Or use the attack provided by [@davidbombal](https://github.com/davidbombal): <br />
Windows:
```
cd attack_and_simulation \
python davidbombal_portscan_attack.py
```
MacOS or Linux:
```
cd attack_and_simulation \
sudo python3 davidbombal_portscan_attack.py
```
### ARP spoofing attack
Windows:
```
cd attack_and_simulation \
python arp_spoofing_simulation.py
```
MacOS or Linux:
```
cd attack_and_simulation \
sudo python3 arp_spoofing_simulation.py
```
### DNS amplification attack
Windows:
```
cd attack_and_simulation \
python dns_amplification_simulation.py
```
MacOS or Linux:
```
cd attack_and_simulation \
sudo python3 dns_amplification_simulation.py
```

## Demonstration
Watch this [YouTube video](https://youtu.be/d4lKryjiN84) for a demonstration of how to use the IDS.
