import matplotlib.pyplot as plt
import numpy as np
import math

fig = plt.figure(figsize=(6,4))
point_size = 50
point_alpha = 1

lambda_name = [1,3,5]
seclvl 	=	[128, 192, 256]
tau 		= 	[[8,9,10,11,12,13,14,15,16,17,18],	
				[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],	
				[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]]

size 		=	[[3120,3250,3380,3510,3640,3770,3900,4030,4160,4290,4420],
				[6976,7170,7364,7558,7752,7946,8140,8334,8528,8722,8916,9110,9304,9498,9692],
				[12626,12884,13142,13400,13658,13916,14174,14432,14690,14948,15206,15464,15722,15980,16238,16496,16754,17012,17270,17528]]

sign_time	=	[[58,23,8,4.5,2,1.3,1,0.6,0.4,0.3,0.3],
				[153,76,32,18,9.8,7.6,5.1,3.6,2.8,2.4,1.7,1.5,1.1,1,0.9],	
				[128,75,35,22,17.2,12.8,9.3,6.6,4.7,4.4,3.7,2.9,2.6,2.2,2,1.7,1.5,1.5,1.3,1.2]]

ver_time 	=	[[58,25,8,4.4,2,1.4,0.9,0.6,0.4,0.3,0.3],
				[154,69,35,19,9.7,7.5,5.1,3.7,2.8,2.4,1.7,1.5,1.1,1,0.9],	
				[128,69,41,24,19.1,12.7,9.3,6.7,5.9,4.1,3.7,2.8,2.6,2.2,2,1.7,1.4,1.5,1.3,1.2]]

for name, lamb, ta, si, sti, vti in zip(lambda_name, seclvl, tau, size, sign_time, ver_time):

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
	# plt.title('Tau-Size-Time Trade-off (Rain-4)')
	#plt.grid()
	# showing legend
	#plt.legend()
	plt.savefig("tau_size_time_Rain_4_" + str(lamb) + ".svg", format="svg")
	plt.clf()

	#break
