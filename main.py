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

episod_length = 300 # in seconds
step_length = 5 # in seconds
window_size = 2 * 60 * 60

# choice == True - False - traffic marked as malicious; choice == False - traffic marked as benign
class Event:
    def __init__ (start, stop, choise): 
        self.start = start
        self.stop = stop
        self.choise = choise

#data = [0.2, 0.3, 0.25, 0.249, 0.001]
#data = [0.001, 0.999]
#print (normalizedEntrophy (data))

def reward (N_11, N_12, N_21, N_22):
    return (P_0 - C_0) * N_11 - (C_0 + C_1) * N_12 - C_2 * N_21 + P_1 * N_22

def gamma (N_11, N_21):
    return N_11 / (N_11 + N_21)

def theta (N_12, N_22):
    return N_12 / (N_12 + N_22)

# only descrete number of states is available
def getPossibleStates ():
    possible_thetas = [state for state in np.arange (0.05, 1, 0.05)]
    possible_gammas = [state for state in np.arange (0.05, 1, 0.05)]
    return (possible_gammas, possible_thetas)

# only descrete number of actions (== theta values) is available
def getPossibleActions ():
    return [state for state in np.arange (0.05, 1, 0.05)]    

def getInitialTheta (actions):
    n = len (actions)
    ind = random.randint (0, n - 1)
    return actions[ind]

def getInitialState (states):
    length1 = len (states[0])
    length2 = len (states[1])

    ind1 = random.randint (0, length1 - 1)
    ind2 = random.randint (0, length2 - 1)
    return (states[0][ind1], states[0][ind2])

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

def getCurrentState (df):
    # TODO should be written
    return 0

def getTheta (state, q_table):
    # TODO should be written
    return 0

def convertToAction (theta):
    # TODO should be written
    return 0

def GetReward (actions):
    # TODO should be written
    return 0

def SecondMax (q_table, state):
    # TODO should be written
    return 0


def plotThresholds (df, attack_df):
    global alpha, gamma, eos, SECONDS_PER_DAY, episod_length, step_length, window_size

    # TODO (end_time - start_time) / episod_lensth (5 s) = episod_limit
    episod_limit = 250
    thresholds = []
    states = getPossibleStates ()
    actions = getPossibleActions ()
    theta = getInitialTheta (actions)
    state = getInitialState (states)
    thresholds.append (theta)
    q_table = initializeQTable ()

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
        # TODO End of not tested part of the code

        # Здесь я оставновился
        reward = GetReward (attack_df, events)
        old_state = state
        state = getCurrentState (events, enum_episod * episod_length,
                                 (num_episod + 1) * episod_length)
        q_table[state][action] = q_table[state][action] + alpha * (reward + 
                             gamma * secondMax (q_table, state) - q_table[old_state][action])
        theta = getTheta (state, q_table)
        thresholds.append (theta)
    
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