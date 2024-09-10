#!/usr/bin/python3

import matplotlib.pyplot as plt
import matplotlib.colors as mc
import numpy as np
import random
import pickle
import os

sec_lvl = 128

point_size = 100
point_alpha = 0.4

fig = plt.figure(figsize=(4.5,4.5))

def load_measurements():
    try:
        with open('measurements.pickle', 'rb') as handle:
            measurements = pickle.load(handle)
    except FileNotFoundError as e:
        measurements = {}

    return measurements

measurements = load_measurements()

# for primitives in ["cccc","eccc"]:
for primitives in ["mq1ccs"]:

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

    ax = fig.add_subplot(1, 1, 1)
    major_ticks_x = np.arange(0, 7000, 700)
    minor_ticks_x = np.arange(0, 7000, 70)
    major_ticks_y = np.arange(0, 100, 10)
    minor_ticks_y = np.arange(0, 100, 1)

    ax.set_xticks(major_ticks_x)
    ax.set_xticks(minor_ticks_x, minor=True)
    ax.set_yticks(major_ticks_y)
    ax.set_yticks(minor_ticks_y, minor=True)

    # And a corresponding grid
    ax.grid(which='both')
    # Or if you want different settings for the grids:
    ax.grid(which='minor', alpha=0.2)
    ax.grid(which='major', alpha=0.5)

    plt.scatter(sizes, times, marker = '.', s=point_size, label = 'New BAVC+Tau trade-off', alpha=point_alpha)
    plt.scatter([ x[0] for x in originals ], [x[1] for x in originals], marker = '*', s=point_size, label= 'Old Tau trade-off', alpha=point_alpha)

    for x in originals:
        print("Old ", x)

    for i, x in enumerate(originals):
        t = plt.annotate("    Tau=" + str(i + 8), (x[0], x[1]), fontsize=5)
        t.set_alpha(0.5)

    plt.legend()
    plt.yscale("log")
    plt.xlabel("Signature size (Bytes)")
    plt.ylabel("Signing time (ms)")

    plt.savefig("VCOM_tradeoff"+primitives+".svg")
    print("")
    print("")
    plt.cla()