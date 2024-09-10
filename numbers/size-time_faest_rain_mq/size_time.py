# Side notes
# For BNPP+Rain_3 and Rain_4, we use params
#     f                 s
# (128, R, 57, 23), (128, R, 1615, 13)
# (192, R, 64, 33), (192, R, 1024, 20)
# (256, R, 64, 44), (256, R, 1024, 27)


import matplotlib.pyplot as plt
import numpy as np

fig = plt.figure(figsize=(6,6))
point_size = 100
point_alpha = 0.8

# Common
id_    =            [1,                  2,                 3,                  4,                  5,                  6,                  7,                  8,                 ]
scheme =            ["KuMQuat-2^1",      "KuMQuat-2^8",     "MandaRain-3",      "MandaRain-4",      "FAESTER-EM",       "FAESTER",          "FAEST-EM",         "FAEST"            ]
marker =            ["x",                "x",               "+",                "+",                "o",                "o",                "s",                "s"]
color  =            ["blue",             "magenta",         "green",            "red",              "gold",             "pink",             "darkorange",       "green",           ]
params =            [['    s','    f'], ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f'],  ['    s','    f']  ]
sizeL1 =            [[2555,3028],       [3389,3984],        [2890,3588],        [3082,3876],        [4138,5300],        [4594,6052],        [4566,5696],        [5006,6336]        ]
sizeL3 =            [[0,0],             [0,0],              [0,0],              [0,0],              [0,0],              [0,0],              [10824,13912],      [12744,16792]      ]
sizeL5 =            [[0,0],             [0,0],              [0,0],              [0,0],              [0,0],              [0,0],              [20956,26736],      [22100,28400]      ]

# KeyGen
keygen_time_L1 =    [[0,0],             [0,0],              [0.0018,0.0018],   [0.0025,0.0025],     [0.0005,0.0005],    [0.0006,0.0005]    ]
keygen_time_L3 =    [[0,0],             [0,0],              [0.0026,0.0026],   [0.0032,0.0032],     [0.0012,0.0012],    [0.0021,0.0022]    ]
keygen_time_L5 =    [[0,0],             [0,0],              [0.0035,0.0035],   [0.0047,0.0047],     [0.0024,0.0025],    [0.003,0.0035]     ]

# Signinig
sign_time_L1 =      [[3.771,0.467],     [3.074,0.411],      [2.8,0.346],        [2.876,0.371],      [2.9,0.45],         [2.776,0.396],      [4.581,0.448],      [4.768,0.445]     ]
sign_time_L3 =      [[0,0],             [0,0],              [9.8,1],           [9.820,1.157],       [0,0],              [0,0],              [10.57,1.08],       [10.85,1.18]       ]
sign_time_L5 =      [[0,0],             [0,0],              [12.3,1.5],        [12.8,1.7],          [0,0],              [0,0],              [14.07,1.56],       [14.37,1.63]       ]

# Verify
verify_time_L1 =    [[5.744,1.049],     [6.316,0.982],      [5.895,0.807],      [6.298,0.817],      [6.54,1.026],       [6.13,0.885],       [4.381,0.444],      [4.749,0.443]     ]
verify_time_L3 =    [[0,0],             [0,0],              [9.8,1],           [9.747,1.135],       [0,0],              [0,0],              [10.88,1.08],       [10.85,1.17]       ]
verify_time_L5 =    [[0,0],             [0,0],              [12.9,1.5],        [12.7,1.7],          [0,0],              [0,0],              [14.11,1.58],       [14.36,1.58]       ]


#L1
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
major_ticks_x = np.arange(0, 7000, 700)
minor_ticks_x = np.arange(0, 7000, 70)
major_ticks_y = np.arange(0, 6, 0.6)
minor_ticks_y = np.arange(0, 6, 0.06)

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
    mark = marker[i - 1]
    if ti[0] == 0 or si[0] == 0:
        continue
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
plt.legend()
plt.savefig("sign_time_faest_rain_mq_128.svg", format="svg")
plt.clf()

#L1
# Size-Verify Time
ax = fig.add_subplot(1, 1, 1)
major_ticks_x = np.arange(0, 7000, 700)
minor_ticks_x = np.arange(0, 7000, 70)
major_ticks_y = np.arange(0, 6, 0.6)
minor_ticks_y = np.arange(0, 6, 0.06)

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
    mark = marker[i - 1]
    if ti[0] == 0 or si[0] == 0:
        continue
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
plt.legend()
plt.savefig("verify_time_faest_rain_mq_128.svg", format="svg")
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


