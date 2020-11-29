import math



class AtackDetectionEntity (object):

    def __init__(self, initial_threshold, learning_rate, greedy_factor,
                 discount_factor, window_size, entries_per_slot,
                 num_thresholds, num_states):
        """Constructor"""
        assert initial_threshold >= 0 and initial_threshold <= math.log2(entries_per_slot),
        'Initial threshold sholudn\'t be less then zero or more than the maximum entropy.'
        assert learning_rate >= 0 and learning_rate <= 1,
        'Requirments from learning rate definition.'
        assert greedy_factor >= 0 and greedy_factor <= 1,
        'Requirments from greedy factor definition.'
        assert discount_factor >= 0 and discount_factor <= 1,
        'Requirments from discount factor definition.'
        assert window_size >= 1,
        'It sholud be at least one slot in episode.'
        assert entries_per_slot >= 1,
        'it should be at least one entry in slot.'
        assert num_thresholds >= 1,
        'It should be at least one threshold.'
        assert num_states >= 1,
        'It should be at least one state'

        self.threshold = initial_threshold
        self.q_table = np.array([])
        self.learing_rate = learning_rate
        self.greedy_factor = greedy_factor
        self.discount_factor = discount_factor
        self.window_size = window_size
        self.entries_per_slot = entries_per_slot
        self.num_thresholds = num_thresholds
        # The real number of states will be this number squared
        self.num_states = num_states

    def generate_q_table(self):
       q_table = np.arr        
