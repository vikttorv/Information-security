import math
import random
import numpy as np
import pandas as pd

P_0 = 14.0 #reward in case the attack was detected (detection and attack)
P_1 = 12.0 #reward if (no attack and no detection)
C_0 = 0.0 #penalty for sending an alarm
C_1 = 3.0 #penalty if the alarm is false (detection and no attack)
C_2 = 15.0 #penalty if the attack was missed (no detection and attack)
SECONDS_PER_DAY = 86400 # number of seconds in day

alpha = 0.1
gamma = 0.8
eps = 0.9
actions_list_size = 21
gamma_list_size = 21
theta_list_size = 21

episod_length = 300 # in seconds
step_length = 5 # in seconds
window_size = 2 * 60 * 60

# choice == True - traffic marked as malicious; choice == False - traffic marked as benign
class Event:
    def __init__ (start, end, choise): 
        self.start = start
        self.end = end
        self.choise = choise

#data = [0.2, 0.3, 0.25, 0.249, 0.001]
#data = [0.001, 0.999]
#print (normalizedEntrophy (data))

def gamma (N_11, N_21):
    return N_11 / (N_11 + N_21)

def theta (N_12, N_22):
    return N_12 / (N_12 + N_22)

# only descrete number of states is available
def getPossibleStates ():
    possible_thetas = [state for state in np.arange (0, 1.05, 0.05)]
    possible_gammas = [state for state in np.arange (0, 1.05, 0.05)]
    return (possible_gammas, possible_thetas)

# only descrete number of actions (== theta values) is available
def getPossibleActions ():
    return [state for state in np.arange (0, 1.05, 0.05)]    

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
    n = len (actions)
    ind = random.randint (0, n - 1)
    return ind

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
    return getEntropy (probs) / math.log2 (len (probs))

# TODO Time in seconds. The initial time is the time of the first received packet
# TODO  Function wasn't tested
def updateEntropyDict (df, entropy_dict, start_time, end_time):
    new_df = pd.DataFrame ()
    if bool (entropy_dict): # dict is empty
        new_df = df.loc[df['time'] >= start_time and df['time'] <= start_time]
    else:
        new_df = df.loc[df['time'] > start_time and df['time'] <= start_time]
    for value in new_df["value"]:
        entropy_dict[value] += 1

    return entropy_dict

# TODO Not tested
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

    Returns
    -------
    tuple
        (n_11, n_12, n_21, n_22)        
    """
    n_11 = 0 
    n_12 = 0 
    n_21 = 0 
    n_22 = 0 
    for event in events:
        is_attack = False
        for ind in range (len(attack_df.index)):
            # attack happened
            if (event.start >= attack_df["start_time"][ind] 
                and event.start < attack_df["end_time"][ind]) or
               (event.end > attack_df["start_time"][ind]
                and event.end <= attack_df["end_time"][ind]):
                if event.choise == True:
                    n_11 += 1
                    is_attack = True
                    break
                else:
                    n_21 += 1
                    is_attack = True
                    break
        if is_attack:
            continue
        else:
            if event.choise == True:
                n_12 += 1
            else:
                n_22 += 1
                
    return (n_11, n_12, n_21, n_22)


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
    return (P_0 - C_0) * events_counters[0] - (C_0 + C_1) * events_counters[1] -
           C_2 * events_counters[2] + P_1 * events_counters[3]

# TODO Not tested
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
    gamma_raw = float (n_11) / (float (n_11) + float (n_21)) 
    theta_raw = float (n_12) / (float (n_12) + float (n_22))
    min_dist1 = 1
    target_ind1 = 0
    min_dist1 = 1
    target_ind2 = 0 
    for ind1 in range (states[0]):
        if math.fabs (states[0][ind1] - gamma_raw) <= min_dist1:
            min_dist1 = math.fabs (states[0][ind1] - gamma_raw)
            target_ind1 = ind1

    for ind2 in range (states[1]):
        if math.fabs (states[1][ind2] - theta_raw) <= min_dist2:
            min_dist2 = math.fabs (states[1][ind2] - theta_raw)
            target_ind2 = ind2
    
    return (target_ind1, target_ind2)

# TODO Not tested
def getTheta (q_table, state_ind):
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

    if (random.uniform (0, 1) < eps):
        max_value = -100000000000
        max_ind = 0
        for ind in range (actions_list_size):
            if q_table[state_ind][ind] > max_value:
                max_ind = ind
                max_value = q_table[ind]
        return max_ind
    else:
        return random.randint (0, actions_list_size - 1)

def plotThresholds (df, attack_df):
    global alpha, gamma, SECONDS_PER_DAY, episod_length, step_length, window_size
    global gamma_list_size, theta_list_size, actions_list_size

    # TODO (end_time - start_time) / episod_lensth (5 s) = episod_limit
    episod_limit = 250
    thresholds = []
    states = getPossibleStates ()
    actions = getPossibleActions ()
    theta_ind = getInitialTheta (actions)
    theta = actions[theta_ind]
    state = getInitialState (states) # state is tuple of ind in gamma_array and theta_array
    thresholds.append (theta)
    q_table = np.zeros((gamma_list_size * theta_list_size, actions_list_size))

    # the window size will be one 1 hour or episod_length * 24.
    # When data collection time reaches 2 hours, the device will delete the data from the first hour
    first_hour_dict = dict ()
    second_hour_dict = dict ()
    entropy_dict = dict ()
    deleted_data_time = 0 # all data before this time were deleted

    # TODO This part of code isn't tested
    for num_episod in range (0, episod_limit + 1, 1):
        events = []
        for ind in range (0, episod_length, step_length):

            time_now = num_episod * episod_length + ind * step_length
            next_step_time = num_episod * episod_length + ind * (step_length + 1)
            diff = time_now - deleted_data_time
            if diff < window_size / 2:
                first_hour_dict = updateEntropyDict (first_hour_dict)
            elif diff < window_size:
                second_hour_dict = updateEntropyDict (second_hour_dict)
            else:
                deleted_data_time += window_size / 2
                for key in first_hour_dict:
                    entropy_dict[key] -= first_hour_dict[key]
                    assert entropy_dict[key] >= 0
                first_hour_dict = second_hour_dict
                second_hour_dict = dict () 
            
            entropy_dict = updateEntropyDict (df, entropy_dict, time_now, next_step_time)
            if getNormalizedEntrophy (entropy_dict) < theta:
                events.append (Event (time_now, next_step_time, True))
            else:
                events.append (Event (time_now, next_step_time, False))

        events_counters = getEventsCounters (attack_df, events)
        reward = getReward (events_counters)
        old_state = state
        state = getCurrentState (events_counters, states)
        q_table_state_ind = state[0] * theta_list_size + state[1]
        q_table_state_ind_old = old_state[0] * theta_list_size + old_state[1]

        q_table[q_table_state_ind_old][theta_ind] = q_table[q_table_state_ind_old][theta_ind] +
        alpha * (reward + gamma * q_table.max (axis = 1)[q_table_state_ind] -
        q_table[q_table_state_ind_old][theta_ind])

        theta_ind = getTheta (q_table, q_table_state_ind)
        theta = actions[theta_ind]
        thresholds.append (theta)
        # TODO End of not tested part of the code
    
    return thresholds 



def createUtilityHistogram ():
    # TODO Should be written
    pass

def doAllPlots (df):
    plotThresholds (df)
    createUtilityHistogram ()  
    pass

# possible state values


# possible state values are discrete             



#doAllPlots (df)