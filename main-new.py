import math
import random
import numpy as np
import pandas as pd
import sys
from scapy.all import *
import matplotlib.pyplot as plt

P_0 = 14 #reward in case the attack was detected (detection and attack)
P_1 = 2 #reward if (no attack and no detection)
C_0 = 0 #penalty for sending an alarm
C_1 = 3 #penalty if the alarm is false (detection and no attack)
C_2 = 15 #penalty if the attack was missed (no detection and attack)
alpha = 0.1
gamma = 0.8
eps = 0.9
actions_list_size = 51
#gamma_list_size = 52
#theta_list_size = 52
gamma_list_size = 22
theta_list_size = 22
#gamma_list_size = 3
#theta_list_size = 3
episod_limit = 51
max_events_counts = 20 # The maximum number of events saved in memory 

SECONDS_PER_DAY = 86400 # number of seconds in day
GLOBAL_START_TIME = 1527823211.8792
episod_length = 300 # in seconds

"""
Start of data parsers part
"""
def getRealNumRows (input_pcap, mac_addr):
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


def processIp (input_pcap, mac_addr):
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
    global GLOBAL_START_TIME, episod_limit
    ret = getRealNumRows (input_pcap, mac_addr)
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

def processTrafficFlow (input_pcap, mac_addr):
    print('Opening {}...'.format(input_pcap))

    count = 0
    i = 0
    time, start_time = 0, 0
    df = list ()
    for (pkt_data, pkt_metadata,) in RawPcapReader (input_pcap):
        time = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        time = time / 10 ** 6
        ether_pkt = Ether(pkt_data)
        if ether_pkt.dst == mac_addr or ether_pkt.src == mac_addr:
            count += 1
        if (time - start_time > 300):
            #to_write = str (i) + ' ' + str (count) + '\n'
            df.append (count)
            i = i + 1
            count = 0
            #print (to_write)
            start_time = time
    return df

def processSrcPort (input_pcap, mac_addr):
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
    ret = getRealNumRows (input_pcap, mac_addr)
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
        if ether_pkt.dst != mac_addr:
            continue
        elif IP in ether_pkt:
            ip_pkt = ether_pkt[IP]
            if TCP in ip_pkt:
                tcp_pkt = ip_pkt[TCP]
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = tcp_pkt.sport
                count += 1
            elif UDP in ip_pkt:
                udp_pkt = ip_pkt[UDP]
                time = (time / 1000000) - GLOBAL_START_TIME
                df["time"][count] = time
                df["value"][count] = udp_pkt.sport
                count += 1

    print ("Pcap processed")
    return df

def parseAnnotation (filename):
    df = pd.read_csv (filename)
    df = df.rename (columns={str (df.columns[0]): "start_time", str (df.columns[1]): "end_time"})
    df["start_time"] = df["start_time"] - GLOBAL_START_TIME
    df["end_time"] = df["end_time"] - GLOBAL_START_TIME
    return df

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
    ret = getRealNumRows (input_pcap, mac_addr)
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
"""
End of data parsers part
"""



"""
Start of Q-learning core part
"""
# choice == True - traffic marked as malicious; choice == False - traffic marked as benign
class Event:
    def __init__ (self, start, end, choise): 
        self.start = start
        self.end = end
        self.choise = choise

# only descrete number of states is available
def getPossibleStates ():
    # -1000 is the case where gamma == 0 / 0 or theta == 0 / 0
    possible_thetas = [state for state in np.arange (0, 1.05, 0.05)] + [-1000]
    possible_gammas = [state for state in np.arange (0, 1.05, 0.05)] + [-1000]
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
            if (event.start >= (attack_df["start_time"][ind] + 0.5)
                 and event.start < (attack_df["end_time"][ind]) - 0.5) or (
                 event.end > (attack_df["start_time"][ind] + 0.5)) and (
                 event.end <= (attack_df["end_time"][ind] - 0.5)):
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

    theta_raw = 0
    if events_counters[1] + events_counters[3] == 0:
        theta_raw = -1000
    else:              
        theta_raw = float (events_counters[1]) / (float (events_counters[1]) +
                    float (events_counters[3]))

    #print ("gamma_raw = {}; theta_raw = {}".format (gamma_raw, theta_raw))
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
    #print ("gamma = {}; theta = {}".format (states[0][target_ind1], states[1][target_ind2]))
    return (target_ind1, target_ind2)

def getLowerBoundActionInd (entropy, actions):
    for ind in range (0, len(actions), 1):
        if actions[ind] > entropy and ind != 0:
            return ind - 1 
        elif actions[ind] >= entropy and ind == 0:
            return 0
    return len (actions) - 1

def getUpperBoundActionInd (entropy, actions):
    for ind in range (len (actions) - 1, -1, -1):
        if actions[ind] < entropy and ind != len (actions) - 1:
            return ind + 1 
        elif actions[ind] <= entropy and ind == len (actions) - 1:
            return len(actions) - 1
    return 0


def getTheta (q_table, state_ind, old_theta_ind, last_event_type, entropy, actions):
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
    #print ("max ind array = {}".format (max_ind_array))


    if len (max_ind_array[0]) == 1:       
        if (random.uniform (0, 1) < eps):
            return target_index
        else:
            if old_theta_ind == 0:
                return random.randint (0, 2)
            elif old_theta_ind == len (q_table[state_ind]) - 1:
                return random.randint (old_theta_ind - 2, old_theta_ind)
            else:
                return random.randint (old_theta_ind - 1, old_theta_ind + 1)
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
                #print ("min_dist_ind = {}".format (min_dist_ind))
                #print ("min_dist = {}".format (min_dist))
                return min_dist_ind
            # false alarm
            elif last_event_type == 2:
                target_ind = getLowerBoundActionInd (entropy, actions)
                smaller_ind_array = []
                for ind in max_ind_array[0]:
                    if ind == target_ind - 1 or ind == target_ind - 2 or ind == target_ind or ind == target_ind - 3:
                        smaller_ind_array.append (ind)
                if len (smaller_ind_array) == 0:
                    return min_dist_ind
                else:
                    return smaller_ind_array[random.randint (0, len (smaller_ind_array) - 1)]
            # real attacks, but missed
            elif last_event_type == 3:
                target_ind = getUpperBoundActionInd (entropy, actions)
                #higher_ind = min_dist_ind
                #min_dist2 = actions_list_size
                #for ind in max_ind_array[0]:
                #    dist = math.fabs (higher_ind - old_theta_ind)
                #    if ind > old_theta_ind and dist <= min_dist2:
                #        higher_ind = ind
                #        min_dist2 = dist

                #if higher_ind == actions_list_size:
                #    return min_dist_ind
                #else:
                #    return higher_ind
                higher_ind_array = []
                for ind in max_ind_array[0]:
                    if ind == target_ind + 1 or ind == target_ind + 2 or ind == target_ind or ind == target_ind + 3:
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
            if old_theta_ind == 0:
                return random.randint (0, 2)
            elif old_theta_ind == len (q_table[state_ind]) - 1:
                return random.randint (old_theta_ind - 2, old_theta_ind)
            else:
                return random.randint (old_theta_ind - 1, old_theta_ind + 1)

def getThresholds (df, attack_df):
    global alpha, gamma, SECONDS_PER_DAY, episod_length, episod_limit
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
        #print ("events counters = {}; last event type = {}".format (events_counters, last_event_type))
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
            #print ("Old state row in q-table after changing = {}".format (q_table[q_table_state_ind_old]))            
            #print ("New state row in q-table = {}".format (q_table[q_table_state_ind]))            
            if len (entropy_dict) == 1 or len (entropy_dict) == 0:
                theta_ind = getTheta (q_table, q_table_state_ind, theta_ind, last_event_type, 0, actions)
            else:
                theta_ind = getTheta (q_table, q_table_state_ind, theta_ind, last_event_type, getNormalizedEntropy (entropy_dict), actions)
            #print ("Theta ind = {}; theta = {}\n\n\n\n".format (theta_ind, actions[theta_ind]))
            theta = actions[theta_ind]
        if constant_theta_events_counters == [0, 0, 0, 0]:
            pass
        else:
            constant_reward = getReward (constant_theta_events_counters)
            rewards_constant.append (constant_reward)            

        thresholds.append (theta)
    return (thresholds, rewards, rewards_constant) 
"""
End of Q-learning core part
"""

"""
Start of plotters part
"""
def getEntropyValues (df):
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

def plotEntropyWithThreshold (df, thresholds):
    global episod_limit
    entropy_values = getEntropyValues (df)
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

def plotEntropy (df):
    global episod_limit
    entropy_values = getEntropyValues (df)
    plt.plot(np.arange (1, episod_limit + 2, 1), entropy_values, marker = 'None',
             linestyle = '-', color = 'k', label = 'Entropy')
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
    print ("static = {}".format (static))
    print ("rf = {}".format (reinforcement))
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

def plotTrafficFlow (df):
    plt.figure(figsize=(10, 3))
    plt.plot(np.arange (0, len(df), 1), df, marker = 'None', linestyle = '-', color = "b", label = 'Traffic')
    plt.xlabel('Time')
    plt.ylabel('# Packets')
    plt.grid()
    plt.title("Traffic flow")
    plt.legend(loc='best')
    plt.gca().set(xlim=(0, 250), ylim=(0, 20000))
    plt.savefig("figures/entropy_" + sys.argv[0].split('.')[0] + ".png")
"""
End of plotters part
"""

def doAllPlots ():
    """
    Threshold and utility graphs for dst + src IP address + entropy for IP 
    """
    #df = processIp ("18-06-01-1-attack.pcap", "ec:1a:59:79:f4:89")
    #df.to_csv ("df.csv", index=False)
    df = pd.read_csv ("df.csv")
    attack_df = parseAnnotation ("ec1a5979f489.csv")
    ret = plotThresholds (df, attack_df)
    plotEntropyWithThreshold (df, ret[2])
    createUtilityHistogram (ret[0], ret[1])  

    """
    Traffic flow graph
    """
    #df = processTrafficFlow ("18-06-01-short.pcap", "ec:1a:59:79:f4:89")
    #plotTrafficFlow (df)

    """
    Entropy for source port
    """
    #df = processSrcPort ("18-06-01-short.pcap", "ec:1a:59:79:f4:89")
    #plotEntropy (df)

    """
    Entropy for destination port
    """ 
    #df = processDstPort ("18-06-01-short.pcap", "ec:1a:59:79:f4:89")
    #plotEntropy (df)    

    """
    It will be implemented next day
    df = processPorts ("18-06-01.pcap", "ec:1a:59:79:f4:89")
    attack_df = parseAnnotation ("ec1a5979f489.csv")
    ret = plotThresholds (df, attack_df)
    plotEntropy (df, attack_df, ret[2])
    createUtilityHistogram (ret[0], ret[1])  

    df = processProtocols ("18-06-01.pcap", "ec:1a:59:79:f4:89")
    attack_df = parseAnnotation ("ec1a5979f489.csv")
    ret = plotThresholds (df, attack_df)
    plotEntropy (df, attack_df, ret[2])
    createUtilityHistogram (ret[0], ret[1])  
    """
    return

if __name__ == "__main__":
    doAllPlots ()
