import random
from lfsr import *
import pandas as pd

POLY_DEG_MIN, POLY_DEG_MAX = 3, 9
SEQLEN_MIN, SEQLEN_MAX = 32, 1024
NUM_DATA = 16384 * 2
# Split according to 8:1:1 rule
TRAIN_NUM_DATA = int(NUM_DATA * 0.8)
VAL_NUM_DATA = int(NUM_DATA * 0.1)
TEST_NUM_DATA = NUM_DATA - TRAIN_NUM_DATA - VAL_NUM_DATA


def get_random_polynomial():
    deg = random.randint(POLY_DEG_MIN, POLY_DEG_MAX)
    coeff = [0] * (deg + 1)
    coeff[0] = 1
    coeff[deg] = 1
    for i in range(1, deg):
        coeff[i] = random.randint(0, 1)
    return Polynomial(coeff)


def get_random_lfsr():
    poly = get_random_polynomial()
    initial_states = [random.randint(0, 1) for _ in range(poly.deg)]
    return LFSR(poly, initial_states)


def get_random_data():
    while True:
        lfsr = get_random_lfsr()
        period = lfsr.get_period_bruteforce()
        if period < 3:
            continue
        if period * 2 > SEQLEN_MIN:
            continue
        seq_len = random.randint(period * 2, SEQLEN_MAX)
        seq = lfsr.generate_n_bits(seq_len)
        return lfsr, seq, period


def generate_data(num_data):
    data = []
    for i in range(num_data):
        lfsr, seq, period = get_random_data()
        poly = ''.join([str(x) for x in lfsr.poly.coeff])
        initial_states = ''.join([str(x) for x in lfsr.initial_states])
        seq = ''.join([str(x) for x in seq])
        data.append({'poly': poly, 'initial_states': initial_states,
                    'seq': seq, 'period': period})
    return data


def save_data(data, fname):
    pd_file = pd.DataFrame(data)
    pd_file.to_csv(fname, index=False)


all_data = generate_data(NUM_DATA)
train_data = all_data[:TRAIN_NUM_DATA]
val_data = all_data[TRAIN_NUM_DATA:TRAIN_NUM_DATA + VAL_NUM_DATA]
test_data = all_data[TRAIN_NUM_DATA + VAL_NUM_DATA:]
save_data(train_data, 'train.csv')
save_data(val_data, 'val.csv')
save_data(test_data, 'test.csv')
