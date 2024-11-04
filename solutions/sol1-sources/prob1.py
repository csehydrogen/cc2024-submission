from lfsr import *
import random

deg = 128
poly_poplist = [0, 1, 2, 7, 128]
coeff = [1 if deg-i in poly_poplist else 0 for i in range(deg+1)]
poly = Polynomial(coeff)  # x^128 + x^7 + x^2 + x + 1
print("Polynomial: ", poly)

initial_states = [random.randint(0, 1) for _ in range(deg)]
initial_states_str = ''.join([str(b) for b in initial_states])
print("Initial states: ", initial_states_str)

lsfr = LFSR(poly, initial_states)
bitstream = lsfr.generate_n_bits(1024)
bitstream_str = ''.join([str(b) for b in bitstream])
print("First 1024 bitstream: ", bitstream_str)
