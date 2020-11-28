import math

P_0 = 14.0 #reward in case the attack was detected (detection and attack)
P_1 = 12.0 #reward if (no attack and no detection)
C_0 = 0.0 #penalty for sending an alarm
C_1 = 3.0 #penalty if the alarm is false (detection and no attack)
C_2 = 15.0 #penalty if the attack was missed (no detection and attack)

alpha = 0.1
gamma = 0.8
eps = 0.9

def entrophy (probs):
    assert sum (probs) == 1
    ent = 0.0
    for prob in probs:
        ent += prob * math.log (prob)
    return ent

def normalizedEntrophy (probs):
    assert sum (probs) == 1
    return entrophy (probs) / math.log (len (probs))

#data = [0.2, 0.3, 0.25, 0.249, 0.001]
#data = [0.001, 0.999]
#print (normalizedEntrophy (data))

def Reward (N_11, N_12, N_21, N_22):
    return (P_0 - C_0) * N_11 - (C_0 + C_1) * N_12 - C_2 * N_21 + P_1 * N_22

def Gamma (N_11, N_21):
    return N_11 / (N_11 + N_21)
def Theta (N_12, N_22):
    return N_12 / (N_12 + N_22)

print (Reward (2, 3, 4, 1))
print (Gamma (2, 4))
print (Theta (3, 7))
