from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import sys
import math
import matplotlib.pyplot as plt
import numpy as np

def process_pcap():
    filename = "18-06-01-short.pcap";
    print('Opening {}...'.format(filename))

    count = 0
    i = 0
    time, start_time = 0, 0
    df = list ()
    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
        time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        time = time / 10 ** 6
        ether_pkt = Ether(pkt_data)
        if ether_pkt.dst == "ec:1a:59:79:f4:89" or ether_pkt.src == "ec:1a:59:79:f4:89":
            count += 1
        if (time - start_time > 300):
            to_write = str (i) + ' ' + str (count) + '\n'
            df.append (count)
            i = i + 1
            count = 0
            print (to_write)
            start_time = time
    return df

def plot (df):
    plt.figure(figsize=(10, 3))
    plt.plot(np.arange (0, len(df), 1), df, marker = 'None', linestyle = '-', color = "b", label = 'Traffic')
    plt.xlabel('Time')
    plt.ylabel('# Packets')
    plt.grid()
    plt.title("Traffic flow")
    plt.legend(loc='best')
    plt.gca().set(xlim=(0, 250), ylim=(0, 20000))
    plt.savefig("entropy_" + sys.argv[0].split('.')[0] + ".png")

df = process_pcap ()
plot (df)
