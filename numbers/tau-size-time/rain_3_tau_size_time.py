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

size 		=	[[2992,3106,3220,3334,3448,3562,3676,3790,3904,4018,4132],
				[6688,6858,7028,7198,7368,7538,7708,7878,8048,8218,8388,8558,8728,8898,9068],
				[12082,12308,12534,12760,12986,13212,13438,13664,13890,14116,14342,14568,14794,15020,15246,15472,15698,15924,16150,16376]]

sign_time	=	[[51.97,28.68,8.21,4.2,2.2,1.4,0.9,0.7,0.4,0.4,0.3],
				[147.3,79.6,32.9,18.5,9.8,7.5,5.1,3.7,2.4,2.1,1.6,1.4,1,0.9,0.9],	
				[125,74,36,22,16,12,8,6,5.7,4.2,3.3,2.7,2.3,2,1.9,1.5,1.4,1.3,1.2,1]]

ver_time 	=	[[58.56,23.16,8.35,4.1,2.2,1.4,0.9,0.7,0.4,0.4,0.3],
				[148,72.3,35.7,19.9,9.8,7.5,5.1,3.6,2.4,2.1,1.6,1.4,1,0.9,0.9],	
				[127,68,42,25,18,12,8,6,5.7,4.2,3.4,2.6,2.3,2,1.9,1.5,1.3,1.3,1.2,1]]

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
	# plt.title('Tau-Size-Time Trade-off (Rain-3)')
	#plt.grid()
	# showing legend
	#plt.legend()
	plt.savefig("tau_size_time_Rain_3_" + str(lamb) + ".svg", format="svg")
	plt.clf()

	#break
