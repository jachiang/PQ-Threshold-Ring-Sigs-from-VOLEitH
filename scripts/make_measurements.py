#!/usr/bin/python3

import matplotlib.pyplot as plt
import matplotlib.colors as mc
import numpy as np
import random
import pickle
import os
import argparse

CLI=argparse.ArgumentParser()
CLI.add_argument(
  "--taus",  
  type=str,
  default="9,10,11,12,13,14,15,16" 
)
CLI.add_argument(
    "--primitives",
    type=str,
    default="cccc"
)
CLI.add_argument(
    "--sl",
    type=int,
    default=128
)
CLI.add_argument(
    "-j",
    type=int,
    default=1
)


# parse the command line
args = CLI.parse_args()
taus = list(map(int, args.taus.split(",")))
primitives = args.primitives
sec_lvl = args.sl
make_threads = args.j

treshold_stride = 1 # 1 for full parameter search
w_stride = 1 # 1 for full parameter search

print("sec_lvl: %r" % sec_lvl)
print("primitives: %r" % primitives)
print("taus: %r" % taus)

def load_measurements():
    try:
        with open('measurements.pickle', 'rb') as handle:
            measurements = pickle.load(handle)
    except FileNotFoundError as e:
        measurements = {}

    return measurements

def store_measurements(measurements):
    with open('measurements.pickle', 'wb') as handle:
        pickle.dump(measurements, handle, protocol=pickle.HIGHEST_PROTOCOL)

measurements = load_measurements()

Delete = False
if Delete:
    new_measurements = {}

    for x in measurements:
        if measurements[x][4] != "cccc" or measurements[x][5] != 9:
            new_measurements[x] = measurements[x]

    measurements = new_measurements
    store_measurements(measurements)

def get_measurement(sec_lvl,primitives,tau,w,treshold):
    global measurements

    name = f"sec{sec_lvl}_{primitives}_{tau}_{w}_{treshold}_avx2"

    if name in measurements:
        return measurements[name]

    print("compile " + name)
    os.popen(f"make -j{make_threads} " + name).read()
    
    print("run " + name)
    out = os.popen(f"./Additional_Implementations/{name}/{name}_bench '[mybench]'").readlines()
    bytes = None
    signing_time = None
    verification_time = None
    for x in out:
        if "signature bytes: " in x:
            bytes = int( x[17:] )
            print("bytes = ", bytes)
        if "sign time: " in x:
            signing_time = float( x[11:] )
            print("sign time = ", signing_time)
        if "verify time: " in x:
            verification_time = float( x[13:] )
            print("verify time = ", verification_time)
    
    entry = (bytes, signing_time, verification_time, sec_lvl, primitives, tau, w, treshold)
    if bytes is None or signing_time is None or verification_time is None:
        print("measurement failed!")
        print(entry)
        exit()
    
    print(name, entry)
    measurements = load_measurements()
    measurements[name] = entry
    store_measurements(measurements)

    os.popen(f"rm -rf ./Additional_Implementations/{name}").read()

    return entry

get_measurement(128, "cccc", 11, 0, -1)
get_measurement(128, "cccc", 16, 0, -1)
get_measurement(128, "eccc", 11, 0, -1)
get_measurement(128, "eccc", 16, 0, -1)


for tau in taus:

    _, base_signing_time, _, _, _, _, _, _  = get_measurement(sec_lvl, primitives, tau, 0, sec_lvl)

    print("base signing time:", base_signing_time)

    w = 6
    for treshold in range(sec_lvl-8,0,-treshold_stride):

        entry = get_measurement(sec_lvl, primitives, tau, w, treshold)
        best_sign_time = entry[1]
        bytes = entry[0]

        # search for w with best signing time
        while True:

            print(treshold, w, best_sign_time, bytes)

            if w > 0:
                entry = get_measurement(sec_lvl, primitives, tau, w-1, treshold)
                if entry[1] < best_sign_time:
                    best_sign_time = entry[1]
                    w = w-1
                    continue

            entry = get_measurement(sec_lvl, primitives, tau, w+1, treshold)
            if entry[1] < best_sign_time:
                best_sign_time = entry[1]
                w = w+1
                continue

            break

        if best_sign_time > 1.5*base_signing_time:
            break

        
        