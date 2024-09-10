#!/usr/bin/python3

import matplotlib.pyplot as plt
import matplotlib.colors as mc
import numpy as np
import random
import pickle
import os

sec_lvl = 128

def load_measurements():
    try:
        with open('measurements.pickle', 'rb') as handle:
            measurements = pickle.load(handle)
    except FileNotFoundError as e:
        measurements = {}

    return measurements

measurements = load_measurements()

for primitives in ["cccc","eccc"]:

    filtered = [ x for x in measurements.values() if x[3] == sec_lvl and x[4] == primitives ]

    # throw away non-optimal measurements
    filtered.sort()

    F = [filtered[0]]
    print(F[-1])
    for i in range(1,len(filtered)):
        if filtered[i][1] < F[-1][1]:
            F.append(filtered[i])
            print(F[-1])
    filtered = F

    sizes = [ x[0] for x in filtered ]
    times = [ x[1] for x in filtered ]

    originals = [ x for x in measurements.values() if x[3] == sec_lvl and x[4] == primitives and x[6] == 0 and x[7] == -1]

    plt.scatter(sizes, times, marker = '.', label = 'Optimized')
    plt.scatter([ x[0] for x in originals ], [x[1] for x in originals], marker = '*', label= 'Original')

    plt.legend()
    plt.yscale("log")
    plt.xlabel("Signature size (Bytes)")
    plt.ylabel("Signing time (ms)")

    plt.savefig("VCOM_tradeoff"+primitives+".png")
    print("")
    print("")
    plt.cla()