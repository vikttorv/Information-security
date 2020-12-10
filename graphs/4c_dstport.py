import math
import random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
#from scapy.utils import RawPcapReader
#from scapy.layers.l2 import Ether
#from scapy.layers.inet import IP, TCP
from scapy.all import *
import sys

P_0 = 14 #reward in case the attack was detected (detection and attack)
P_1 = 12 #reward if (no attack and no detection)
C_0 = 0 #penalty for sending an alarm
C_1 = 3 #penalty if the alarm is false (detection and no attack)
C_2 = 15 #penalty if the attack was missed (no detection and attack)
SECONDS_PER_DAY = 86400 # number of seconds in day
GLOBAL_START_TIME = 0

alpha = 0.1
gamma = 0.8
eps = 0.9
actions_list_size = 51
gamma_list_size = 52
theta_list_size = 52


episod_limit = 0
episod_length = 300 # in seconds
step_length = 5 # in seconds
#window_size = 2 * 60 * 60

def parseAnnotation (filename):
    df = pd.read_csv (filename)
    df = df.rename (columns={str (df.columns[0]): "start_time", str (df.columns[1]): "end_time"})
    df["start_time"] = df["start_time"] - GLOBAL_START_TIME
    df["end_time"] = df["end_time"] - GLOBAL_START_TIME
    return df


def get_real_num_rows (input_pcap):
    global episod_limit
    num_rows = 0
    max_time_unix = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader (input_pcap):
        if max_time_unix == 0:
            max_time_unix =  ((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) / 1000000
        ether_pkt = Ether (pkt_data)
        if ether_pkt.src != "ec:1a:59:79:f4:89":
            continue
        elif IP in ether_pkt:
            ip_pkt = ether_pkt[IP]
            if TCP in ip_pkt or UDP in ip_pkt:
                time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
                if max_time_unix < time:
                    max_time_unix = time / 1000000
                num_rows += 1

    return (num_rows, max_time_unix)

def processDstPort (input_pcap, mac_addr):
    """
    Parse .pcap file

    Parameters
    ----------
    input_pcap : list
        .pcap file to parse

    Returns
    -------
    pd.DataFrame
        DataFrame created from pcap file ('time' + 'value' columns)
    """
    #pcap = rdpcap (input_pcap)
    global GLOBAL_START_TIME, episod_limit
    ret = get_real_num_rows (input_pcap)
    num_rows = ret[0]
    end_time_unix = ret[1]
    print ("num_rows = {}; end time unix = {}".format (num_rows, end_time_unix))
    print (num_rows)
    df = pd.DataFrame(index=range (num_rows), columns=['time', 'value'])
    is_start_time_set = False
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader (input_pcap):
        time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        if not is_start_time_set:
            GLOBAL_START_TIME = time / 1000000
            episod_limit = math.ceil ((end_time_unix - GLOBAL_START_TIME) / episod_length)
            print (episod_limit)
            is_start_time_set = True

        ether_pkt = Ether (pkt_data)
        if ether_pkt.src != mac_addr:
            continue
        elif IP in ether_pkt:
            ip_pkt = ether_pkt[IP]
            if TCP in ip_pkt:
                tcp_pkt = ip_pkt[TCP]
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = tcp_pkt.dport
                count += 1
            elif UDP in ip_pkt:
                udp_pkt = ip_pkt[UDP]
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = udp_pkt.dport
                count += 1

    print ("Pcap processed")
    return df

def getEntropy (probs):
    ent = 0.0
    total_number = 0
    for key in probs:
        total_number += probs[key]

    for key in probs:
        if probs[key] != 0:
            ent -= (probs[key] / total_number) * math.log2 ((probs[key] / total_number))
    return ent

def getNormalizedEntropy (probs):
    assert len (probs) > 1

    return getEntropy (probs) / math.log2 (len (probs))

# Time in seconds. The initial time is the time of the first received packet
def updateEntropyDict (df, entropy_dict, start_time, end_time):
    new_df = pd.DataFrame ()
    if bool (entropy_dict): # dict is not empty
        new_df = df.loc[(df['time'] > start_time) & (df['time'] <= end_time)]
    else: # dict is empty
        new_df = df.loc[(df['time'] >= start_time) & (df['time'] <= end_time)]
    for value in new_df["value"]:
        if value in entropy_dict.keys():
            entropy_dict[value] += 1
        else:
            entropy_dict[value] = 1

    return entropy_dict

def getEntropyValues (df, attack_df):
    global episod_limit

    entropy_values = []
    for num_episod in range (0, episod_limit + 1, 1):
        entropy_dict = dict ()
        time_now = num_episod * episod_length
        next_episod_time = (num_episod + 1) * episod_length
        entropy_dict = updateEntropyDict (df, entropy_dict, time_now, next_episod_time)

        if len (entropy_dict) == 0 or len (entropy_dict) == 1:
            if len (entropy_values) != 0:
                entropy_values.append (entropy_values[num_episod - 1])
            else:
                entropy_values.append (0)
        else:
            entropy_values.append (getNormalizedEntropy (entropy_dict))

    return entropy_values

def plotEntropy (df, attack_df):
    global episod_limit
    thresholds = getEntropyValues (df, attack_df)
    plt.figure(figsize=(10, 5))
    plt.plot(np.arange (1, episod_limit + 2, 1), thresholds, marker = 'None', linestyle = '-', color = "m", label = 'Entropy')
    plt.xlabel('Time')
    plt.ylabel('Entropy')
    plt.grid()
    plt.title("Dst Port")
    plt.legend(loc='best')
    plt.gca().set(xlim=(0, 250), ylim=(0, 1))
    plt.savefig("entropy_" + sys.argv[0].split('.')[0] + ".png")

def doAllPlots ():
    df = processPcap ("18-06-01-short.pcap")
    attack_df = parseAnnotation ("00166cab6b88.csv")
    #plotThresholds (df, attack_df)
    plotEntropy (df, attack_df)
    #createUtilityHistogram ()
    pass

doAllPlots ()
