
# GF(2) polynomial
class Polynomial:

    # coeff is a list of coefficients, starting from the highest degree
    # coeff = [p_m, p_m-1, p_m-2, ..., p_0]
    # ex: x^3 + x + 1 -> Polynomial([1, 0, 1, 1])
    def __init__(self, coeff):
        assert coeff[0] == 1
        self.deg = len(coeff) - 1
        self.coeff = coeff

    def __str__(self):
        ret = " + ".join([f"x^{self.deg-i}" for i in range(self.deg)
                         if self.coeff[i] == 1])
        if ret.endswith("^1"):
            ret = ret[:-2]
        if self.coeff[-1] == 1:
            ret += " + 1"
        return ret

    def __eq__(self, other):
        return self.coeff == other.coeff

    def __add__(self, other):
        if self.deg < other.deg:
            return other + self
        coeff = self.coeff.copy()
        for i in range(other.deg+1):
            coeff[self.deg-i] ^= other.coeff[other.deg-i]
        while coeff[0] == 0:
            coeff.pop(0)
        return Polynomial(coeff)

    def __mul__(self, other):
        coeff = [0] * (self.deg + other.deg + 1)
        for i in range(self.deg+1):
            for j in range(other.deg+1):
                coeff[i+j] ^= self.coeff[i] * other.coeff[j]
        while coeff[0] == 0:
            coeff.pop(0)
        return Polynomial(coeff)


class LFSR:
    # Initial states are stored in a list, from the highest degree to the lowest
    # Like: [s_m-1, s_m-2, ..., s_0]
    # At each step, the rightmost bit is returned, and the states are updated according to the polynomial
    def __init__(self, poly, initial_states):
        assert len(initial_states) == poly.deg
        self.poly = poly
        self.initial_states = initial_states
        self.states = initial_states
        self.len = len(initial_states)

    def step(self):
        ret = self.states[-1]
        next_bit = 0
        for i in range(self.len):
            next_bit ^= self.poly.coeff[self.len - i] \
                * self.states[self.len - 1 - i]
        self.states = [next_bit] + self.states[:-1]
        return ret

    def generate_n_bits(self, n):
        self.states = self.initial_states
        return [self.step() for _ in range(n)]

    def get_period_bruteforce(self):
        self.states = self.initial_states
        state_list = []
        state_list.append(self.states.copy())
        while True:
            self.step()
            if self.states in state_list:
                period = len(state_list) - state_list.index(self.states)
                break
            state_list.append(self.states.copy())
        return period
