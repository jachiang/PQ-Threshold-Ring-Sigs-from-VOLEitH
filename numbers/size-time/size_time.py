# Side notes
# For BNPP+Rain_3 and Rain_4, we use params
#     f                 s
# (128, R, 57, 23), (128, R, 1615, 13)
# (192, R, 64, 33), (192, R, 1024, 20)
# (256, R, 64, 44), (256, R, 1024, 27)


import matplotlib.pyplot as plt
import numpy as np

fig = plt.figure(figsize=(8,8))
point_size = 100
point_alpha = 0.8

# Common
id_    =            [1,                 2,                  3,                  4,                  5,                  6,                  7,                  8,                  9,                  10,                      11,                      10,                 11,                     12,                 13,                 14,                     15,                     16,                     17,                     18,                     19,                     20,                         21                      ]
scheme =            ["KuMQuat-2^1",     "KuMQuat-2^8",      "MandaRain-3",      "MandaRain-4",      "FAESTER-EM",       "FAESTER",          "FAEST-EM",         "FAEST",            "Helium-LOWMC",     "Helium-AES",           "Rainier-3",            "Rainier-4",        "BNPP-LOWMC",           "BNPP-Rain-3",      "BNPP-Rain-4",      "Biscuit",              "Mira",                 "MiRitH",               "MQOM",                 "Perk",                 "Ryde",                 "SDitH",                    "AIMer"                 ]
marker =            ["x",               "x",                "D",                "D",                "s",                "s",                "^",                "^"]
color  =            ["red",             "green",            "red",              "green",            "red",              "green",            "red",              "green",             "lightpink",        "lavenderblush",        "lavender",             "lightcoral",       "paleturquoise",        "red",              "saddlebrown",      "darkorange",           "gold",                 "olive",                "green",                "darkslategrey",        "cyan",                 "blue",                     "magenta"               ]
params =            [['    s','    f'], ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],      ['    s','    f'],      ['    s','    f'],  ['    s','    f'],      ['    s','    f'],  ['    s','    f'],  ['    s','    f'],      ['    s','    f'],      ['    as','    bf'],    ['    31s','    251f'], ['    f3','    s5'],    ['    s','    f'],      ['    h256','    t251'],    ['    1f','    4s']     ]
sizeL1 =            [[2555,3028],       [2890,3588],        [2890,3588],        [3082,3876],        [4138,5300],        [4594,6052],        [4566,5696],        [5006,6336],        [6582,7495],        [9888,11420],           [5536,8544],            [6080,9600],        [6906,9849],            [4048,5248],        [4464,5984],        [4758,6726],            [5640,7376],            [5673,9105],            [6352,7850],            [8350,6060],            [5956,7446],            [8496,10684],               [5904,3840]             ]
sizeL3 =            [[7368,8728],       [7096,12952],       [7368,8728],        [7752,9304],        [10824,13912],      [12744,16792],      [10824,13912],      [12744,16792],      [0,0],              [0,0],                  [12128,18944],          [13328,21296],      [0,0],                  [8768,11216],       [9728,12800],       [11349,15129],          [11779,15540],          [12440,18459],          [13846,17252],          [18800,13800],          [12933,16380],          [19544,25964],              [13080,8352]            ]
sizeL5 =            [[13916,16496],     [12860,23280],      [13212,15472],      [13916,16496],      [20956,26736],      [22100,28400],      [20956,26736],      [22100,28400],      [0,0],              [0,0],                  [21280,33440],          [23392,37600],      [0,0],                  [15712,19872],      [17440,22688],      [20192,27348],          [20762,27678],          [21795,33048],          [24158,30092],          [33300,24200],          [22802,29134],          [33924,45676],              [25152,15392]           ]

# KeyGen
keygen_time_L1 =    [[0.1,0.1],          [0.1,0.1],         [0.0018,0.0018],    [0.0025,0.0025],    [0.0005,0.0005],    [0.0006,0.0005],    [0.0005,0.0005],    [0.0006,0.0005],    [0.01,0.01],        [0.002,0.002],          [0.002,0.002],          [0.002,0.002],      [0.004,0.002],          [0.002,0.002],      [0.003,0.003],      [0.019,0.02],           [0.031,0.031],          [0.035,0.031],          [0.12,0.09],            [0.075,0.082],          [0.009,0.009],          [1.98,0.24],                [0.012,0.012]           ]
keygen_time_L3 =    [[0.1,0.1],          [0.1,0.1],         [0.0026,0.0026],    [0.0032,0.0032],    [0.0012,0.0012],    [0.0021,0.0022],    [0.0012,0.0012],    [0.0021,0.0022],    [0,0],              [0,0],                  [0.002,0.002],          [0.003,0.003],      [0,0],                  [0.004,0.004],      [0.006,0.005],      [0.044,0.047],          [0.074,0.083],          [0,0],                  [0.51,0.44],            [0.12,0.13],            [0.012,0.012],          [2.24,0.31],                [0.027,0.027]           ]
keygen_time_L5 =    [[0.1,0.1],          [0.1,0.1],         [0.0035,0.0035],    [0.0047,0.0047],    [0.0024,0.0025],    [0.003,0.0035],     [0.0024,0.0025],    [0.003,0.0035],     [0,0],              [0,0],                  [0.003,0.003],          [0.004,0.004],      [0,0],                  [0.008,0.008],      [0.012,0.012],      [0.073,0.073],          [0.174,0.173],          [0,0],                  [1.36,0.95],            [0.2,0.21],             [0.016,0.016],          [4.47,0.56],                [0.066,0.066]           ]

# Signinig
sign_time_L1 =      [[3.771,0.467],     [3.074,0.411],      [2.8,0.346],        [2.876,0.371],      [2.9,0.45],         [2.776,0.396],      [4.581,0.448],      [4.768,0.445],      [13.31,7.6],        [7.56,4.87],            [3.33,0.5],             [3.85,0.57],        [58.12,3.55],           [14.33,0.94],       [16.33,1.06],       [15.44,2.5],            [9.37,7.9],             [68.74,1.26],           [5.2,1.5],              [4.61,21.5],            [5.4,1.09],             [3.31,0.74],                [1,39.2]                ]
sign_time_L3 =      [[0,0],             [0,0],              [9.8,1],            [9.820,1.157],      [10.57,1.08],       [10.85,1.18],       [10.57,1.08],       [10.85,1.18],       [0,0],              [0,0],                  [6.82,1.07],            [7.86,1.24],        [0,0],                  [18.7,2],           [21.6,2.3],         [123.84,15.88],         [24.39,21.6],           [0,0],                  [14.34,4.26],           [9.02,49.48],           [9.37,2.34],            [5.55,1.86],                [2.5,98.43]             ]
sign_time_L5 =      [[0,0],             [0,0],              [12.3,1.5],         [12.8,1.7],         [14.07,1.56],       [14.37,1.63],       [14.07,1.56],       [14.37,1.63],       [0,0],              [0,0],                  [10.9,1.66],            [12.02,1.8],        [0,0],                  [28.7,3],           [33.73,3.5],        [240.87,27.66],         [63.67,65.12],          [0,0],                  [28.87,10.94],          [21.61,0],              [19.31,4.89],           [10.86,3.61],               [4.9,79.72]             ]

# Verify
verify_time_L1 =    [[5.744,1.049],     [6.316,0.982],      [5.895,0.807],      [6.298,0.817],      [6.54,1.026],       [6.13,0.885],       [4.381,0.444],      [4.749,0.443],      [13.12,7.9],        [7.35,4.42],            [3.31,0.47],            [3.81,0.54],        [58.79,3.52],           [13.66,0.88],       [15.56,1],          [15.27,2.27],            [8.8,7.69],            [68.26,1.14],           [4.83,1.31],            [2.77,11.65],           [4.52,0.89],            [2.9,0.11],                 [0.95,34.41]            ]
verify_time_L3 =    [[0,0],             [0,0],              [9.8,1],            [9.747,1.135],      [10.88,1.08],       [10.85,1.17],       [10.88,1.08],       [10.85,1.17],       [0,0],              [0,0],                  [6.76,0.98],            [7.7,1.12],         [0,0],                  [18.22,1.9],        [21,2.24],          [123.5,14.78],           [23.64,21.86],         [0,0],                  [13.14,3.71],           [5.75,32.15],           [8.3,1.98],             [4.55,0.28],                [2.37,94.63]            ]
verify_time_L5 =    [[0,0],             [0,0],              [12.9,1.5],         [12.7,1.7],         [14.11,1.58],       [14.36,1.58],       [14.11,1.58],       [14.36,1.58],       [0,0],              [0,0],                  [10.86,1.54],           [11.9,1.73],        [0,0],                  [28.3,2.9],         [33.2,3.45],        [240.24,25.82],          [62.10,65.19],         [0,0],                  [28.35,9.55],           [14.58,0],              [17.15,4.15],           [9.3,0.52],                 [4.73,186.58]           ]


# #L1
# # Size-Keygen Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 0.1, 0.01)
# minor_ticks_x = np.arange(0, 0.1, 0.001)
# major_ticks_y = np.arange(0, 2, 1)
# minor_ticks_y = np.arange(0, 2, 0.1)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, keygen_time_L1, sizeL1):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     if ti[0] > 0.1 or ti[1] > 0.1:    # focusing on just the last 0.013
#         continue
#     plt.scatter(ti, [1,1], label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], 1), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Keygen Time (ms)')
# # frequency label
# #plt.ylabel('Size (Bytes)')
# # plot title
# # plt.title('Keygen Overview')
# # showing legend
# plt.legend()
# plt.savefig("keygen_time_128.svg", format="svg")
# plt.clf()

#L1
# Size-Sign Time
ax = fig.add_subplot(1, 1, 1)
major_ticks_x = np.arange(0, 13000, 1300)
minor_ticks_x = np.arange(0, 13000, 130)
major_ticks_y = np.arange(0, 100, 10)
minor_ticks_y = np.arange(0, 100, 2)

ax.set_xticks(major_ticks_x)
ax.set_xticks(minor_ticks_x, minor=True)
ax.set_yticks(major_ticks_y)
ax.set_yticks(minor_ticks_y, minor=True)

# And a corresponding grid
ax.grid(which='both')
# Or if you want different settings for the grids:
ax.grid(which='minor', alpha=0.2)
ax.grid(which='major', alpha=0.5)
for i, sch, col, par, ti, si in zip(id_, scheme, color, params, sign_time_L1, sizeL1):
    if i < 9:
        mark = marker[i - 1]
    else:
        mark = "."
    if ti[0] == 0 or si[0] == 0:
        continue
    # if ti[0] > 40 or si[0] > 12000 or ti[1] > 40 or si[1] > 12000:
    #     continue
    plt.scatter(si, ti, label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
    for i, txt in enumerate(par):
        t = plt.annotate(txt, (si[i], ti[i]), fontsize=12)
        t.set_alpha(0.5)
# x-axis label
plt.xlabel('Signature Size (Bytes)')
# frequency label
plt.ylabel('Signing Time (ms)')
plt.yscale('log')
plt.legend(fancybox=True, framealpha=0.6, ncol=2, loc='upper right', bbox_to_anchor=(1.01, 1.01))
plt.tight_layout()
# plot title
# plt.title('Signature Overview')
# showing legend
# plt.legend()
plt.savefig("sign_time_128.svg", format="svg")
plt.clf()

#L1
# Size-Verify Time
ax = fig.add_subplot(1, 1, 1)
major_ticks_x = np.arange(0, 13000, 1300)
minor_ticks_x = np.arange(0, 13000, 130)
major_ticks_y = np.arange(0, 100, 10)
minor_ticks_y = np.arange(0, 100, 2)

ax.set_xticks(major_ticks_x)
ax.set_xticks(minor_ticks_x, minor=True)
ax.set_yticks(major_ticks_y)
ax.set_yticks(minor_ticks_y, minor=True)

# And a corresponding grid
ax.grid(which='both')
# Or if you want different settings for the grids:
ax.grid(which='minor', alpha=0.2)
ax.grid(which='major', alpha=0.5)
for i, sch, col, par, ti, si in zip(id_, scheme, color, params, verify_time_L1, sizeL1):
    if i < 9:
        mark = marker[i - 1]
    else:
        mark = "."
    if ti[0] == 0 or si[0] == 0:
        continue#
    # if ti[0] > 40 or si[0] > 12000 or ti[1] > 40 or si[1] > 12000:
    #     continue
    plt.scatter(si, ti, label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
    for i, txt in enumerate(par):
        t = plt.annotate(txt, (si[i], ti[i]), fontsize=12)
        t.set_alpha(0.5)
# x-axis label
plt.xlabel('Signature Size (Bytes)')
# frequency label
plt.ylabel('Verifying Time (ms)')
plt.yscale('log')
plt.legend(fancybox=True, framealpha=0.6, ncol=2, loc='upper right', bbox_to_anchor=(1.01, 1.01))
plt.tight_layout()
# plot title
# plt.title('Signature Overview')
# showing legend
# plt.legend()
plt.savefig("verify_time_128.svg", format="svg")
plt.clf()


# ######################################################################################
# ######################################################################################
# ######################################################################################

# #L3
# # Size-Keygen Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 0.15, 0.015)
# minor_ticks_x = np.arange(0, 0.15, 0.0015)
# major_ticks_y = np.arange(0, 2, 1)
# minor_ticks_y = np.arange(0, 2, 0.1)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, keygen_time_L3, sizeL3):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     if ti[0] > 0.15 or ti[1] > 0.15:    # focusing on just the last 0.013
#         continue
#     plt.scatter(ti, [1,1], label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], 1), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Keygen Time (ms)')
# # frequency label
# #plt.ylabel('Size (Bytes)')
# # plot title
# # plt.title('Keygen Overview')
# # showing legend
# plt.legend()
# plt.savefig("keygen_time_192.svg", format="svg")
# plt.clf()

# #L3
# # Size-Sign Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 140, 20)
# minor_ticks_x = np.arange(0, 140, 4)
# major_ticks_y = np.arange(0, 27000, 2700)
# minor_ticks_y = np.arange(0, 27000, 270)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, sign_time_L3, sizeL3):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     # if ti[0] > 100 or si[0] > 22000 or ti[1] > 100 or si[1] > 22000:
#     #     continue
#     plt.scatter(ti, si, label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], si[i]), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Signing Time (ms)')
# # frequency label
# plt.ylabel('Size (Bytes)')
# # plot title
# # plt.title('Signature Overview')
# # showing legend
# plt.legend()
# plt.savefig("sign_time_192.svg", format="svg")
# plt.clf()

# # Size-Verify Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 140, 20)
# minor_ticks_x = np.arange(0, 140, 4)
# major_ticks_y = np.arange(0, 27000, 2700)
# minor_ticks_y = np.arange(0, 27000, 270)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# #L3
# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, verify_time_L3, sizeL3):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     # if ti[0] > 100 or si[0] > 20000 or ti[1] > 100 or si[1] > 20000:
#     #     continue
#     plt.scatter(ti, si, label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], si[i]), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Verifying Time (ms)')
# # frequency label
# plt.ylabel('Size (Bytes)')
# # plot title
# plt.title('Signature Overview')
# # showing legend
# plt.legend()
# plt.savefig("verify_time_192.svg", format="svg")
# plt.clf()

# ######################################################################################
# ######################################################################################
# ######################################################################################

# #L5
# # Size-Keygen Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 0.2, 0.02)
# minor_ticks_x = np.arange(0, 0.2, 0.002)
# major_ticks_y = np.arange(0, 2, 1)
# minor_ticks_y = np.arange(0, 2, 0.1)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, keygen_time_L5, sizeL5):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     if ti[0] > 0.2 or ti[1] > 0.2:    # focusing on just the last 0.013
#         continue
#     plt.scatter(ti, [1,1], label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], 1), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Keygen Time (ms)')
# # frequency label
# #plt.ylabel('Size (Bytes)')
# # plot title
# # plt.title('Keygen Overview')
# # showing legend
# plt.legend()
# plt.savefig("keygen_time_256.svg", format="svg")
# plt.clf()

# #L5
# # Size- Sign Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 260, 20)
# minor_ticks_x = np.arange(0, 260, 5)
# major_ticks_y = np.arange(0, 50000, 5000)
# minor_ticks_y = np.arange(0, 50000, 500)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, sign_time_L5, sizeL5):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     # if ti[0] > 200 or si[0] > 40000 or ti[1] > 200 or si[1] > 40000:
#     #     continue
#     plt.scatter(ti, si, label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], si[i]), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Signing Time (ms)')
# # frequency label
# plt.ylabel('Size (Bytes)')
# # plot title
# # plt.title('Signature Overview')
# # showing legend
# plt.legend()
# plt.savefig("sign_time_256.svg", format="svg")
# plt.clf()

# #L5
# # Size- Verify Time
# ax = fig.add_subplot(1, 1, 1)
# major_ticks_x = np.arange(0, 260, 20)
# minor_ticks_x = np.arange(0, 260, 5)
# major_ticks_y = np.arange(0, 50000, 5000)
# minor_ticks_y = np.arange(0, 50000, 500)

# ax.set_xticks(major_ticks_x)
# ax.set_xticks(minor_ticks_x, minor=True)
# ax.set_yticks(major_ticks_y)
# ax.set_yticks(minor_ticks_y, minor=True)

# # And a corresponding grid
# ax.grid(which='both')
# # Or if you want different settings for the grids:
# ax.grid(which='minor', alpha=0.2)
# ax.grid(which='major', alpha=0.5)
# for i, sch, col, par, ti, si in zip(id_, scheme, color, params, verify_time_L5, sizeL5):
#     mark = "."
#     if i < 6:
#         mark = "x"
#     if ti[0] == 0 or si[0] == 0:
#         continue
#     # if ti[0] > 200 or si[0] > 30000 or ti[1] > 200 or si[1] > 30000:
#     #     continue
#     plt.scatter(ti, si, label= sch, color= col, marker= mark, s=point_size, alpha=point_alpha)
#     for i, txt in enumerate(par):
#         t = plt.annotate(txt, (ti[i], si[i]), fontsize=6)
#         t.set_alpha(0.5)
# # x-axis label
# plt.xlabel('Verifying Time (ms)')
# # frequency label
# plt.ylabel('Size (Bytes)')
# # plot title
# # plt.title('Signature Overview')
# # showing legend
# plt.legend()
# plt.savefig("verify_time_256.svg", format="svg")
# plt.clf()


