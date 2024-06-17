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
python3 IDS.py
```

## IDS Modification
The IDS allows for adjustments to global variables to optimise detection sensitivity for different networks and devices such as:
- `SYNFLOOD_THRESHOLD`: the minimum number of unresponded SYN packets in the period of `MEMORY_RESET_TIME` to alert a SYN flood attack detection (higher means less sensitive).
- `UDPFLOOD_THRESHOLD`: the minimum number of ICMP packets in response to UDP packets in the period of `MEMORY_RESET_TIME` to alert a UDP flood attack detection (higher means less sensitive).
- `PORT_SCAN_THRESHOLD`: the minimum number of ports accessed by one device with SYN packets in the period of `MEMORY_RESET_TIME` to alert a port scanning attack detection (higher means less sensitive).
- `DNS_AMP_THRESHOLD`: the minimum number of bytes a DNS response packet to alert a DNS amplification attack detection (higher means less sensitive).
- `TIME_CHECK`: the time in seconds to check the "detection system memories" for any detection that exceeds the thresholds. Once exceeded, a detection log will be outputted and the memory for that detection system will be cleared.
- `VERBOSE`: log levels
    - -1 for no logs
    - 0 for basic attack detection logs **(recommended)**
    - 1 for other networking logs (useful for monitoring and adjusting thresholds)

Other global variables that are adjustable, but not recommended:
- `MEMORY_RESET_TIME`: the time in seconds to store packet information for "detection system memories" before clearing/resetting
- `CHECK_RESETTABLE`: the time in seconds to check if a detection system memory is clearable/resettable
