import matplotlib.pyplot as plt
import numpy as np
import math

fig = plt.figure(figsize=(6,4))
point_size = 50
point_alpha = 0.3

aes_lambda_name = [1,3,5]
aes_lambda 	=	[128, 192, 256]
tau 		= 	[[8,9,10,11,12,13,14,15,16,17,18],	
				[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],	
				[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]]

size 		=	[[4208,4474,4740,5006,5272,5538,5804,6070,6336,6602,6868],
				[10720,11226,11732,12238,12744,13250,13756,14768,15274,15780,16286,16792,17298,17804],
				[18950,19580,20210,20840,21470,22100,22730,23360,23990,24620,25250,25880,26510,27140,27770,28400,29030,30290,30920]]

sign_time	=	[[56.58,23.18,8.29,4.44,2.29,1.49,0.97,0.74,0.44,0.43,0.32],
				[169.97,89.70,37.61,19.94,10.85,8.2,5.4,4.39,2.87,1.81,1.5,1.18,1.13,0.92],	
				[143.85,82.07,42.76,29.02,18.47,14.4,10.16,7.83,6.18,4.72,3.86,3.27,2.71,2.26,2.08,1.64,1.57,1.34,1.16]]

ver_time 	=	[[63.35,24.94,8.26,4.42,2.25,1.51,0.97,0.73,0.44,0.43,0.3],
				[167.93,80.7,39.64,20.88,10.85,8.2,5.44,4.28,2.87,2.46,1.8,1.17,1.1,0.91],
				[146.5,76.26,47.58,31.91,20.39,15.21,10.31,7.7,6.22,4.55,3.87,3.25,2.72,2.29,2.08,1.59,1.464,1.340,1.13]]

thres = [98,99,100,102,106,116,127]

th_size = [[4530, 4546, 4562, 4594, 4658, 4818, 4994], [5960, 5876, 5892, 5924, 5988, 6148, 6324, 6336]]

th_sign_time = [[10.952, 8.136, 6.561, 5.552, 4.602, 4.391, 4.395, 4.435], [0.544, 0.507, 0.478, 0.488, 0.444, 0.469, 0.437, 0.457]]

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
		# plt.scatter(st+vt, s, color=c, marker= '.', s=point_size, alpha=point_alpha)
		# plt.annotate("   tau="+str(t), (st+vt, s), fontsize=6)
		plt.scatter(st, s, color=c, marker= '.', s=point_size, alpha=point_alpha)
		plt.annotate("   tau="+str(t), (st, s), fontsize=6)

		if t == 11:
			for th_s, th_st, th in zip(th_size[0], th_sign_time[0], thres):
				plt.scatter(th_st, th_s, color='red', marker= '.', s=10, alpha=1)
				plt.annotate("   "+str(th), (th_st, th_s), fontsize=3)

		if t == 16:
			for th_s, th_st, th in zip(th_size[1], th_sign_time[1], thres):
				plt.scatter(th_st, th_s, color='red', marker= '.', s=10, alpha=1)
				plt.annotate("   "+str(th), (th_st, th_s), fontsize=3)
		
		idx += 1

	# x-axis label
	plt.xlabel('time (ms)')
	# frequency label
	plt.ylabel('size (bytes)')
	# plot title
	# plt.title('Tau-Size-Time Trade-off (FAEST)')
	#plt.grid()
	# showing legend
	#plt.legend()
	plt.savefig("tau_size_time_AES_" + str(lamb) + ".svg", format="svg")
	plt.clf()

	#break
