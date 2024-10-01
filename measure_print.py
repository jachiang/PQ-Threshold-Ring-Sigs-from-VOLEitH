import pickle

try:
    with open('measurements.pickle', 'rb') as handle:
        measurements = pickle.load(handle)
except FileNotFoundError as e:
    measurements = {}

def load_measurements():
    try:
        with open('measurements.pickle', 'rb') as handle:
            measurements = pickle.load(handle)
    except FileNotFoundError as e:
        measurements = {}

    return measurements

measurements = load_measurements()

print("signature bytes, signing_time, verification_time, sec_lvl, primitives, tau, w, treshold")

for sec_lvl in [128, 192, 256]:
    for primitives in ["cccs","eccs"]:

        filtered = [ x for x in measurements.values() if x[3] == sec_lvl and x[4] == primitives ]

        # throw away non-optimal measurements
        filtered.sort()

        F = [filtered[0]]
        print(F[-1])