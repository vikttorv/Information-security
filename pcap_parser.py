from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import sys

def process_pcap(input_pcap, output):
    print('Opening {}...'.format(input_pcap))

    f = open (output, 'w')
    f.write ("linux time\t\tsrc IP\n")
    count = 0
    d = dict ()
    for (pkt_data, pkt_metadata,) in RawPcapReader(input_pcap):
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            continue
        if ether_pkt.type != 0x0800:
            print ("Here\n")
            continue

        ip_pkt = ether_pkt[IP]

        time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        time = time / 1000000
        to_write = str (time) + ' ' + str (ip_pkt.src) + '\n'
        f.write (to_write)
        """
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        tcp_pkt = ip_pkt[TCP]

        if (d.count ())
        d[tcp_pkt.dport] += 1
        """

        count += 1

    print('{} contains {} IPv4 packets'.format(input_pcap, count))
    f.close ()

process_pcap (sys.argv[1], sys.argv[2])
