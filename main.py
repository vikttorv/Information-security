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


# old method saved. Please don't delete it before our presentation.
"""
        for ind in range (0, episod_length, step_length):
            time_now = num_episod * episod_length + ind 
            next_step_time = num_episod * episod_length + ind + step_length
            diff = time_now - deleted_data_time
            
            if diff < episod_length:
                first_hour_dict = updateEntropyDict (df, first_hour_dict, time_now, next_step_time)
            elif diff < 2 * episod_length:
                second_hour_dict = updateEntropyDict (df, second_hour_dict, time_now, next_step_time)
            else:
                second_hour_dict = updateEntropyDict (df, second_hour_dict, time_now, next_step_time)
                deleted_data_time += episod_length
                for key in first_hour_dict:
                    entropy_dict[key] -= first_hour_dict[key]
                    assert entropy_dict[key] >= 0
                print ("Here")
                first_hour_dict = second_hour_dict
                second_hour_dict = dict ()
            
            entropy_dict = updateEntropyDict (df, entropy_dict, time_now, next_step_time)
            if len (entropy_dict) == 0 or len (entropy_dict) == 1:
                pass
            elif getNormalizedEntropy (entropy_dict) < theta:
                print (getNormalizedEntropy (entropy_dict))
                events.append (Event (time_now, next_step_time, True))
            else:
                print (getNormalizedEntropy (entropy_dict))
                events.append (Event (time_now, next_step_time, False))
"""






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
#gamma_list_size = 52
#theta_list_size = 52
gamma_list_size = 3
theta_list_size = 3



episod_limit = 0
episod_length = 300 # in seconds
step_length = 5 # in seconds
max_events_counts = 1 # The maximum number of events saved in memory 


# choice == True - traffic marked as malicious; choice == False - traffic marked as benign
class Event:
    def __init__ (self, start, end, choise): 
        self.start = start
        self.end = end
        self.choise = choise

def get_real_num_rows (input_pcap, mac_addr):
    global episod_limit
    num_rows = 0
    max_time_unix = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader (input_pcap):  
        if max_time_unix == 0:
            max_time_unix =  ((pkt_metadata.tshigh << 32) | pkt_metadata.tslow) / 1000000
        ether_pkt = Ether (pkt_data)
        if ether_pkt.dst != mac_addr and ether_pkt.src != mac_addr:
            continue 
        #if IPv6 in ether_pkt:
        #    time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        #    if max_time_unix < time:
        #        max_time_unix = time / 1000000
        #    num_rows += 1       
        elif IP in ether_pkt:
            time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            if max_time_unix < time:
                max_time_unix = time / 1000000
            num_rows += 1
        elif ARP in ether_pkt:
            time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            if max_time_unix < time:
                max_time_unix = time / 1000000
            num_rows += 1

    return (num_rows, max_time_unix)


def processPcap (input_pcap, mac_addr):
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
    ret = get_real_num_rows (input_pcap, mac_addr)
    num_rows = ret[0]
    end_time_unix = ret[1]
    print ("num rows = {}; end time = ".format (num_rows), end='')
    df = pd.DataFrame (index=range (num_rows), columns=['time', 'value'])
    is_start_time_set = False
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader (input_pcap):
        time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        if not is_start_time_set:
            GLOBAL_START_TIME = time / 1000000
            print ("{}; num episods = ".format (end_time_unix - GLOBAL_START_TIME), end='')
            episod_limit = math.ceil ((end_time_unix - GLOBAL_START_TIME) / episod_length)
            print (episod_limit)
            is_start_time_set = True

        ether_pkt = Ether (pkt_data)
        if ether_pkt.dst != mac_addr and ether_pkt.src != mac_addr:
            continue
        #if IPv6 in ether_pkt:     
        #    if  ether_pkt.dst == "00:16:6c:ab:6b:88": 
        #        ipv6_pkt = ether_pkt[IPv6]
        #        time = (time / 1000000) - GLOBAL_START_TIME
        #        df["time"][count] = time
        #        df["value"][count] = ipv6_pkt.src
        #        count += 1
        #    else:
        #        ipv6_pkt = ether_pkt[IPv6]
        #        time = (time / 1000000) - GLOBAL_START_TIME
        #        df["time"][count] = time
        #        df["value"][count] = ipv6_pkt.dst
        #        count += 1

        elif IP in ether_pkt:
            if  ether_pkt.dst == mac_addr: 
                ip_pkt = ether_pkt[IP] 
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = ip_pkt.src
                count += 1
            else:
                ip_pkt = ether_pkt[IP] 
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = ip_pkt.dst
                count += 1   
                     
        elif ARP in ether_pkt:
            if  ether_pkt.dst == mac_addr: 
                arp_pkt = ether_pkt[ARP]
                #if arp_pkt.psrc == "0.0.0.0":
                #    continue 
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = arp_pkt.psrc
                count += 1
            else:
                arp_pkt = ether_pkt[ARP]
                #if arp_pkt.psrc == "0.0.0.0":
                #    continue 
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = arp_pkt.pdst
                count += 1
         

    print ("Pcap processed")
    return df

def parseAnnotation (filename):
    df = pd.read_csv (filename)
    df = df.rename (columns={str (df.columns[0]): "start_time", str (df.columns[1]): "end_time"})
    df["start_time"] = df["start_time"] - GLOBAL_START_TIME
    df["end_time"] = df["end_time"] - GLOBAL_START_TIME
    return df

# only descrete number of states is available
def getPossibleStates ():
    # -1000 is the case where gamma == 0 / 0 or theta == 0 / 0
    possible_thetas = [0, 1, -1000] # [state for state in np.arange (0, 1.02, 0.02)] + [-1000]
    possible_gammas = [0, 1, -1000] # [state for state in np.arange (0, 1.02, 0.02)] + [-1000]
    return (possible_gammas, possible_thetas)

# only descrete number of actions (== theta values) is available
def getPossibleActions ():
    return [action for action in np.arange (0, 1.02, 0.02)]    

def getInitialTheta (actions):
    """
    Get index of initial theta in actions list

    Parameters
    ----------
    actions : list
        The list of possible actions

    Returns
    -------
    int
        index in actions array        
    """
    #n = len (actions)
    #ind = random.randint (0, n - 1)
    return 35

def getInitialState (states):
    """
    Get tuple of initial state indexes in gamma_arrray and theta_array

    Parameters
    ----------
    actions : tuple of lists
        (gamma_array, theta_array)

    Returns
    -------
    tuple of int
        tuple of initial state indexes in gamma_arrray and theta_array       
    """
    length1 = len (states[0])
    length2 = len (states[1])

    ind1 = random.randint (0, length1 - 1)
    ind2 = random.randint (0, length2 - 1)
    return (ind1, ind2)

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

def getEventsCounters (attack_df, events):
    """
    Returns the number of each type of events
    n_11 - the number of authenticated true attacks
    n_12 - the number of false alarms
    n_21 - the number of real attacks, but missed
    n_22 - the number of authenticated benign traffic flows

    Parameters
    ----------
    attack_df : DataFrame
        The data frame with infromation about attack. You should get it from .csv table
    events : list of Event
        The list of events for each time step  
    old_events_counters : tuple of ints 
        The tuple old events counters

    Returns
    -------
    tuple
        (n_11, n_12, n_21, n_22)        
    """
    n_11 = 0 
    n_12 = 0 
    n_21 = 0 
    n_22 = 0 
    event_type = 0
    for event in events:
        is_attack = False
        for ind in range (len(attack_df.index)):
            # attack happened
            if (event.start >= attack_df["start_time"][ind] 
                 and event.start < attack_df["end_time"][ind]) or (
                 event.end > attack_df["start_time"][ind]
                 and event.end <= attack_df["end_time"][ind]):
                if event.choise == True:
                    n_11 += 1
                    event_type = 1
                    is_attack = True
                    break
                else:
                    event_type = 3
                    n_21 += 1
                    is_attack = True
                    break
        if is_attack:
            continue
        else:
            if event.choise == True:
                event_type = 2
                n_12 += 1
            else:
                event_type = 4
                n_22 += 1

    return ([n_11, n_12, n_21, n_22], event_type)


# TODO not tested
def getReward (events_counters):
    """
    Returns the reward for given number of events
        
    Parameters
    ----------
    events_counters : tuple of int
        (n_11, n_12, n_21, n_22)
        n_11 - The number of authenticated true attacks
        n_12 - The number of false alarms
        n_21 - The number of real attacks, but missed
        n_22 - The number of authenticated benign traffic flows

    Returns
    -------
    int
        Reward        
    """
    global P_0, P_1, C_0, C_1, C_2 
    return (P_0 - C_0) * events_counters[0] - (C_0 + C_1) * events_counters[1] - (
           C_2 * events_counters[2] - P_1 * events_counters[3])

def getCurrentState (events_counters, states):
    """
    Returns the the hit rate "gamma" and false alarm rate "theta"
         
    Parameters
    ----------
    events_counters : tuple of int
        (n_11, n_12, n_21, n_22)
        n_11 - The number of authenticated true attacks
        n_12 - The number of false alarms
        n_21 - The number of real attacks, but missed
        n_22 - The number of authenticated benign traffic flows
    states : tuple of two arrays
        (gamma_array, theta_array) where gamma_array - possible gamma values,
                                         theta_array - possible theta values

    Returns
    -------
    tuple of int
        (gamma index in gamma_array, theta index in theta_array)       
    """
    gamma_raw = 0
    if events_counters[0] + events_counters[2] == 0:
        gamma_raw = -1000
    else:
        gamma_raw = float (events_counters[0]) / (float (events_counters[0]) +
                    float (events_counters[2])) 

    if events_counters[1] + events_counters[3] == 0:
        theta_raw = -1000
    else:              
        theta_raw = float (events_counters[1]) / (float (events_counters[1]) +
                    float (events_counters[3]))

    min_dist1 = 1
    target_ind1 = 0
    min_dist2 = 1
    target_ind2 = 0 
    for ind1 in range (len (states[0])):
        if math.fabs (states[0][ind1] - gamma_raw) <= min_dist1:
            min_dist1 = math.fabs (states[0][ind1] - gamma_raw)
            target_ind1 = ind1

    for ind2 in range (len (states[1])):
        if math.fabs (states[1][ind2] - theta_raw) <= min_dist2:
            min_dist2 = math.fabs (states[1][ind2] - theta_raw)
            target_ind2 = ind2
    return (target_ind1, target_ind2)

# TODO Not tested
def getTheta (q_table, state_ind, old_theta_ind, last_event_type):
    """
    Returns the index of the maximum action for state with state_ind with probability that
    is equal to eps and the index of random action with probability that is equal to 1 - eps  
         
    Parameters
    ----------
    q_table : np.array
        Q-table
    state_ind : int
        Number of state in Q-table 

    Returns
    -------
    int
        Index of appropriate actions       
    """
    global eps, actions_list_size
    max_ind_array = np.where (q_table[state_ind] == np.amax (q_table[state_ind]))
    target_index = max_ind_array[0][0]

    if len (max_ind_array[0]) == 1:       
        if (random.uniform (0, 1) < eps):
            return target_index
        else:
            if target_index == 0:
                return random.randint (0, 2)
            elif target_index == len (q_table[state_ind]) - 1:
                return random.randint (target_index - 2, target_index)
            else:
                return random.randint (target_index - 1, target_index + 1)
    else:
        if (random.uniform (0, 1) < eps):
            # find min dist ind
            min_dist = actions_list_size
            min_dist_ind = old_theta_ind
            for ind in range (len (max_ind_array[0])):
                dist = math.fabs (old_theta_ind - max_ind_array[0][ind])
                if min_dist > dist:
                    min_dist = dist
                    min_dist_ind = max_ind_array[0][ind]        
            # authenticated true attacks or benign traffic flows
            if last_event_type == 1 or last_event_type == 4:
                return min_dist_ind
            # false alarm
            elif last_event_type == 2:
                smaller_ind_array = []
                for ind in max_ind_array[0]:
                    if ind < old_theta_ind:
                        smaller_ind_array.append (ind)
                if len (smaller_ind_array) == 0:
                    return min_dist_ind
                else:
                    return  smaller_ind_array[random.randint (0, len (smaller_ind_array) - 1)]
            # real attacks, but missed
            elif last_event_type == 3:
                higher_ind_array = []
                for ind in max_ind_array[0]:
                    if ind > old_theta_ind:
                        higher_ind_array.append (ind)
                if len (higher_ind_array) == 0:
                    return min_dist_ind
                else:
                    return higher_ind_array[random.randint (0, len (higher_ind_array) - 1)]
            else:
                print ("Fatal error: incorrect event type")
                exit (-1)
            return target_index
        else:
            if target_index == 0:
                return random.randint (0, 2)
            elif target_index == len (q_table[state_ind]) - 1:
                return random.randint (target_index - 2, target_index)
            else:
                return random.randint (target_index - 1, target_index + 1)

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

def getThresholds (df, attack_df):
    global alpha, gamma, SECONDS_PER_DAY, episod_length, step_length, episod_limit
    global gamma_list_size, theta_list_size, actions_list_size, max_events_counts

    thresholds = []
    states = getPossibleStates ()
    actions = getPossibleActions ()
    theta_ind = getInitialTheta (actions)
    theta = actions[theta_ind]
    state = getInitialState (states) # state is tuple of ind in gamma_array and theta_array
    thresholds.append (theta)
    q_table = np.zeros((gamma_list_size * theta_list_size, actions_list_size))

    entropy_dict = dict ()
    events = []    
    rewards = []
    rewards_constant = []
    constant_theta = theta
    constant_theta_events = []

    events_counters = [0, 0, 0, 0]
    constant_theta_events_counters = [0, 0, 0, 0]


    for num_episod in range (0, episod_limit + 1, 1):
        entropy_dict = dict ()
        time_now = num_episod * episod_length 
        next_episod_time = (num_episod + 1) * episod_length    
        entropy_dict = updateEntropyDict (df, entropy_dict, time_now, next_episod_time)
        if len (entropy_dict) == 0 or len (entropy_dict) == 1:
            pass
        elif getNormalizedEntropy (entropy_dict) < theta:
            events.append (Event (time_now, next_episod_time, True))
        else:
            events.append (Event (time_now, next_episod_time, False))

        if len (entropy_dict) == 0 or len (entropy_dict) == 1:
            pass
        elif getNormalizedEntropy (entropy_dict) < constant_theta:
            constant_theta_events.append (Event (time_now, next_episod_time, True))
        else:
            constant_theta_events.append (Event (time_now, next_episod_time, False))

        if len (constant_theta_events) > max_events_counts:
            constant_theta_events.pop (0)
        if len (events) > max_events_counts:
            events.pop (0)
             
        ret = getEventsCounters (attack_df, events)
        events_counters = ret[0]
        last_event_type = ret[1]
        constant_theta_events_counters = (getEventsCounters (attack_df, constant_theta_events))[0]
        
        if events_counters == [0, 0, 0, 0]:
            pass
        else:
            reward = getReward (events_counters)
            rewards.append (reward)
 
            old_state = state
            state = getCurrentState (events_counters, states)
            q_table_state_ind = state[0] * theta_list_size + state[1]
            q_table_state_ind_old = old_state[0] * theta_list_size + old_state[1]

            q_table[q_table_state_ind_old][theta_ind] = q_table[q_table_state_ind_old][theta_ind] + (
            alpha * (reward + gamma * q_table.max (axis = 1)[q_table_state_ind] - (
            q_table[q_table_state_ind_old][theta_ind])))

            theta_ind = getTheta (q_table, q_table_state_ind, theta_ind, last_event_type)
            theta = actions[theta_ind]

        if constant_theta_events_counters == [0, 0, 0, 0]:
            pass
        else:
            constant_reward = getReward (constant_theta_events_counters)
            rewards_constant.append (constant_reward)            

        thresholds.append (theta)
    return (thresholds, rewards, rewards_constant) 

def plotEntropy (df, attack_df, thresholds):
    global episod_limit
    entropy_values = getEntropyValues (df, attack_df)
    plt.plot(np.arange (1, episod_limit + 2, 1), entropy_values, marker = 'None',
             linestyle = '-', color = 'k', label = 'Entropy')
    plt.plot(np.arange (0, episod_limit + 2, 1), thresholds, marker = 'None',
             linestyle = '-', color = 'r', label = 'Threshold')
    plt.xlabel ('Time')
    plt.ylabel ('Normalized entropy')
    plt.grid ()
    plt.legend (loc='best')
    plt.savefig ("figures/entropy.png")
    plt.close ()

def plotThresholds (df, attack_df):
    """
    Plot threshold (time) figure
         
    Parameters
    ----------
    df : DataFrame
        DataFrame to analyze
    attack_df : DataFrame
        DataFrame with information about attacks        
    """   
    global episod_limit
 
    ret = getThresholds (df, attack_df)
    thresholds = ret[0]
    rewards = ret[1]
    rewards_constant = ret[2]

    plt.plot(np.arange (0, episod_limit + 2, 1), thresholds, marker = 'None',
             linestyle = '-', color = 'k', label = 'Threshold')
    plt.xlabel ('Time')
    plt.ylabel ('Threshold')
    plt.grid ()
    plt.legend (loc='best')
    plt.savefig ("figures/threshold.png")
    plt.close ()
    return (rewards, rewards_constant, thresholds)

def createUtilityHistogram (rewards_q_mod, rewards_const_mod):
    names = ['WeMo power switch', 'WeMo power switch']

    static = [np.array (rewards_const_mod).mean (), np.array (rewards_const_mod).mean ()]
    reinforcement = [np.array (rewards_q_mod).mean (), np.array (rewards_q_mod).mean ()]

    x = np.arange(len(names))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar (x - width/2, static, width, label='Stat')
    rects2 = ax.bar (x + width/2, reinforcement, width, label='RF')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel ('Utility')
    ax.set_title ('Static vs reinforcement')
    ax.set_xticks (x)
    ax.set_xticklabels (names)
    ax.legend ()
    plt.savefig ("figures/utility.png") 
    return

def doAllPlots ():
    df = processPcap ("18-06-01-short.pcap", "ec:1a:59:79:f4:89")
    attack_df = parseAnnotation ("ec1a5979f489.csv")
    ret = plotThresholds (df, attack_df)
    plotEntropy (df, attack_df, ret[2])
    createUtilityHistogram (ret[0], ret[1])  
    return

doAllPlots ()