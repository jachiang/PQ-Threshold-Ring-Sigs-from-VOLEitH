import matplotlib.pyplot as plt
import numpy as np
import math

fig = plt.figure(figsize=(6,4))
point_size = 50
point_alpha = 1

aes_lambda_name = [1,3,5]
aes_lambda 	=	[128, 192, 256]
tau 		= 	[[8,9,10,11,12,13,14,15,16,17,18],	
				[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],	
				[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]]

size 		=	[[3888,4114,4340,4566,4792,5018,5244,5470,5696,5922,6148],
				[9280,9666,10052,10438,10824,11210,11596,11982,12368,12754,13140,13526,13912,14298,14684],
				[18066,18644,19222,19800,20378,20956,21534,22112,22690,23268,23846,24424,25002,25580,26158,26736,27314,27892,28470,29048]]

sign_time	=	[[55.38,24.59,8.07,4.71,2.26,1.59,0.97,0.74,0.49,0.42,0.32],
				[155.33,83.45,32.48,17.55,10.57,8.17,5.45,3.79,2.82,2.19,1.64,1.38,1.15,1.03,0.9],	
				[131.8,87.93,43.11,24.96,18.08,14.07,11.01,7.09,6.79,4.9,3.94,2.94,2.81,2.35,2.12,1.56,1.54,1.35,1.27,1.05]]

ver_time 	=	[[62.02,26.5,8.09,4.74,2.26,1.6,0.94,0.74,0.49,0.42,0.32],
				[157.34,74.79,35.23,19.16,10.88,8.11,5.31,3.71,2.79,2.33,1.6,1.3,1.15,1.01,0.87],
				[132.91,82.46,47.3,29.12,20.06,14.11,11.06,7.21,6.45,4.83,4,3.03,2.66,2.33,2.14,1.58,1.49,1.36,1.28,1.08]]

for name, lamb, ta, si, sti, vti in zip(aes_lambda_name, aes_lambda, tau, size, sign_time, ver_time):

	ax = fig.add_subplot(1, 1, 1)
	x_floor = math.floor((max(sti)+max(vti) + 1)/100)
	y_floor = math.floor((max(si) + 1)/100)
	major_ticks_x = np.arange(0, max(sti)+max(vti) + 1, x_floor*10)
	minor_ticks_x = np.arange(0, max(sti)+max(vti) + 1, x_floor)
	major_ticks_y = np.arange(0, max(si) + 1, y_floor*10)
	minor_ticks_y = np.arange(0, max(si) + 1, y_floor)
	
	ax.set_xticks(major_ticks_x)
	ax.set_xticks(minor_ticks_x, minor=True)
	ax.set_yticks(major_ticks_y)
	ax.set_yticks(minor_ticks_y, minor=True)

	# And a corresponding grid
	ax.grid(which='both')
	# Or if you want different settings for the grids:
	ax.grid(which='minor', alpha=0.2)
	ax.grid(which='major', alpha=0.5)

	idx = 0
	for t, s, st, vt in zip(ta, si, sti, vti):
		size_score = (max(si) - s)/max(si)*100
		time_score = (max(sti) + max(vti) - st - vt)/(max(sti) + max(vti))*100
		c = ''
		if idx <= len(si)*0.3:
			c = 'magenta'
		elif idx <= len(si)*0.5 and idx > len(si)*0.3:
			c = 'darkblue'
		elif idx <= len(si)*0.8 and idx > len(si)*0.5:
			c = 'cyan'
		else:
			c = 'lime'
		plt.scatter(st+vt, s, color=c, marker= '.', s=point_size, alpha=point_alpha)
		t = plt.annotate("   tau="+str(t), (st+vt, s), fontsize=6)
		t.set_alpha(0.5)
		idx += 1

	# x-axis label
	plt.xlabel('time (ms)')
	# frequency label
	plt.ylabel('size (bytes)')
	# plot title
	# plt.title('Tau-Size-Time Trade-off (FAEST-EM)')
	#plt.grid()
	# showing legend
	#plt.legend()
	plt.savefig("tau_size_time_AES-EM_" + str(lamb) + ".svg", format="svg")
	plt.clf()

	#break
