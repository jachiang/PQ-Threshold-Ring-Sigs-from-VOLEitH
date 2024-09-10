from tabulate import tabulate
import math

B = 16

# AES
aes_lambda_name = [1,3,5]
aes_lambda = [128, 192, 256]
aes_non_linear = [184, 384, 468]
tau = [[8,9,10,11,12,13,14,15,16,17,18],[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]] # # tau for each lambda
table = [['scheme','ell','tau','tau_0','tau_1','k_0','k_1','sk','pk','sig size','lower bound']]

for lambname, lamb, nonlin, lamb_tau in zip(aes_lambda_name, aes_lambda, aes_non_linear, tau):

	# here comes the sk, pk and ell size
	witness = nonlin
	key = int(lamb/8)

	sk_size = int(lamb/8)
	pk_size = int(lamb/8)*2
	ell = (witness + key)*8

	for t in lamb_tau:
		temp = []

		# here comes the siganture size and the lower bound
		temp.append("FAEST-L" + str(lambname) + "_" + str(t)) 		# scheme name
		temp.append(str(ell))															# final ell length
		temp.append(str(t))																# tau size
		t0 = lamb%t
		t1 = t - t0
		k0 = math.ceil(lamb/t)
		k1 = math.floor(lamb/t)
		if (((t0 * k0) + (t1 * k1)) != lamb):
			print(lamb)
			print(t0, t1, k0, k1)
			print((t0 * k0) + (t1 * k1))
			print("FAIL!")
			exit()
		temp.append(str(t0))															# t0 size
		temp.append(str(t1))															# t1 size
		temp.append(str(k0))															# k0 size
		temp.append(str(k1))															# k1 size
		temp.append(str(sk_size))														# sk size
		temp.append(str(pk_size))														# pk size

		sig_size = ((ell + (2*lamb) + B) * (t - 1)) + (lamb + B) + (ell + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128
		lower_bound = ((0 + (2*lamb) + B) * (t - 1)) + (lamb + B) + (0 + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128

		temp.append(str(int(sig_size/8)))
		temp.append(str(int(lower_bound/8)))
		table.append(temp)

	empty = []
	table.append(empty)

print("AES OWF")
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))


print("\n\n\n\n")

# AES-EM

aes_em_lambda_name = [1,3,5]
aes_em_lambda = [128, 192, 256]
aes_em_non_linear = [144, 264, 416]
tau = [[8,9,10,11,12,13,14,15,16,17,18],[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]] # # tau for each lambda
table = [['scheme','ell','tau','tau_0','tau_1','k_0','k_1','sk','pk','sig size','lower bound']]

for lambname, lamb, nonlin, lamb_tau in zip(aes_em_lambda_name, aes_em_lambda, aes_em_non_linear, tau):

	# here comes the sk, pk and ell size
	witness = nonlin
	key = int(lamb/8)

	sk_size = int(lamb/8)
	pk_size = int(lamb/8)*2
	ell = (witness + key)*8

	for t in lamb_tau:
		temp = []

		# here comes the siganture size and the lower bound
		temp.append("FAEST-EM-L" + str(lambname) + "_" + str(t)) 		# scheme name
		temp.append(str(ell))															# final ell length
		temp.append(str(t))																# tau size
		t0 = lamb%t
		t1 = t - t0
		k0 = math.ceil(lamb/t)
		k1 = math.floor(lamb/t)
		if (((t0 * k0) + (t1 * k1)) != lamb):
			print(lamb)
			print(t0, t1, k0, k1)
			print((t0 * k0) + (t1 * k1))
			print("FAIL!")
			exit()
		temp.append(str(t0))															# t0 size
		temp.append(str(t1))															# t1 size
		temp.append(str(k0))															# k0 size
		temp.append(str(k1))															# k1 size
		temp.append(str(sk_size))														# sk size
		temp.append(str(pk_size))														# pk size

		sig_size = ((ell + (2*lamb) + B) * (t - 1)) + (lamb + B) + (ell + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128
		lower_bound = ((0 + (2*lamb) + B) * (t - 1)) + (lamb + B) + (0 + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128

		temp.append(str(int(sig_size/8)))
		temp.append(str(int(lower_bound/8)))
		table.append(temp)

	empty = []
	table.append(empty)

print("AES-EM OWF")
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))


print("\n\n\n\n")

# Rain_3
rain_lambda_name = [1,3,5]
rain_lambda = [128, 192, 256]
rain_non_linear = [2, 2, 2]
tau = [[8,9,10,11,12,13,14,15,16,17,18],[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]] # # tau for each lambda
table = [['scheme','ell','tau','tau_0','tau_1','k_0','k_1','sk','pk','sig size','lower bound']]

for lambname, lamb, nonlin, lamb_tau in zip(rain_lambda_name, rain_lambda, rain_non_linear, tau):

	# here comes the sk, pk and ell size
	witness = nonlin*int(lamb/8)
	key = int(lamb/8)

	sk_size = int(lamb/8)
	pk_size = int(lamb/8)*2
	ell = (witness + key)*8

	for t in lamb_tau:
		temp = []

		# here comes the siganture size and the lower bound
		temp.append("FAEST-Rain3-L" + str(lambname) + "_" + str(t)) 		# scheme name
		temp.append(str(ell))															# final ell length
		temp.append(str(t))																# tau size
		t0 = lamb%t
		t1 = t - t0
		k0 = math.ceil(lamb/t)
		k1 = math.floor(lamb/t)
		if (((t0 * k0) + (t1 * k1)) != lamb):
			print(lamb)
			print(t0, t1, k0, k1)
			print((t0 * k0) + (t1 * k1))
			print("FAIL!")
			exit()
		temp.append(str(t0))															# t0 size
		temp.append(str(t1))															# t1 size
		temp.append(str(k0))															# k0 size
		temp.append(str(k1))															# k1 size
		temp.append(str(sk_size))														# sk size
		temp.append(str(pk_size))														# pk size

		sig_size = ((ell + (2*lamb) + B) * (t - 1)) + (lamb + B) + (ell + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128
		lower_bound = ((0 + (2*lamb) + B) * (t - 1)) + (lamb + B) + (0 + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128

		temp.append(str(int(sig_size/8)))
		temp.append(str(int(lower_bound/8)))
		table.append(temp)

	empty = []
	table.append(empty)

print("RAIN-3 OWF")
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))


print("\n\n\n\n")


# Rain_4
rain_lambda_name = [1,3,5]
rain_lambda = [128, 192, 256]
rain_non_linear = [3, 3, 3]
tau = [[8,9,10,11,12,13,14,15,16,17,18],[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]] # # tau for each lambda
table = [['scheme','ell','tau','tau_0','tau_1','k_0','k_1','sk','pk','sig size','lower bound']]

for lambname, lamb, nonlin, lamb_tau in zip(rain_lambda_name, rain_lambda, rain_non_linear, tau):

	# here comes the sk, pk and ell size
	witness = nonlin*int(lamb/8)
	key = int(lamb/8)

	sk_size = int(lamb/8)
	pk_size = int(lamb/8)*2
	ell = (witness + key)*8

	for t in lamb_tau:
		temp = []

		# here comes the siganture size and the lower bound
		temp.append("FAEST-Rain4-L" + str(lambname) + "_" + str(t)) 		# scheme name
		temp.append(str(ell))															# final ell length
		temp.append(str(t))																# tau size
		t0 = lamb%t
		t1 = t - t0
		k0 = math.ceil(lamb/t)
		k1 = math.floor(lamb/t)
		if (((t0 * k0) + (t1 * k1)) != lamb):
			print(lamb)
			print(t0, t1, k0, k1)
			print((t0 * k0) + (t1 * k1))
			print("FAIL!")
			exit()
		temp.append(str(t0))															# t0 size
		temp.append(str(t1))															# t1 size
		temp.append(str(k0))															# k0 size
		temp.append(str(k1))															# k1 size
		temp.append(str(sk_size))														# sk size
		temp.append(str(pk_size))														# pk size

		sig_size = ((ell + (2*lamb) + B) * (t - 1)) + (lamb + B) + (ell + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128
		lower_bound = ((0 + (2*lamb) + B) * (t - 1)) + (lamb + B) + (0 + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128

		temp.append(str(int(sig_size/8)))
		temp.append(str(int(lower_bound/8)))
		table.append(temp)

	empty = []
	table.append(empty)

print("RAIN-4 OWF")
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))


print("\n\n\n\n")


# MQ
mq_lambda_name = [1,3,5]
mq_lambda = [128, 192, 256]
mq_p = [1,8]	# pow of 2
mq_n = [[152,48],[224,72],[320,96]] # n for each lambda and pow of 2
tau = [[8,9,10,11,12,13,14,15,16,17,18],[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]] # # tau for each lambda
table = [['scheme','ell','tau','tau_0','tau_1','k_0','k_1','sk','pk','sig size','lower bound']]


for lambname, lamb, lamb_n, lamb_tau in zip(mq_lambda_name, mq_lambda, mq_n, tau):

	for p, n in zip(mq_p,lamb_n):

		# here comes the sk, pk and ell size
		witness = 0
		key = n*p
		y = n*p

		sk_size = (y + 7)//8
		pk_size = int(lamb/8 + (y + 7)//8)
		ell = ((witness + key + 7)//8)*8

		for t in lamb_tau:
			temp = []
			# here comes the siganture size and the lower bound
			temp.append("FAEST-MQ-2^" + str(p) + "-L" + str(lambname) + "_" + str(t)) 		# scheme name
			temp.append(str(ell))															# final ell length
			temp.append(str(t))																# tau size
			t0 = lamb%t
			t1 = t - t0
			k0 = math.ceil(lamb/t)
			k1 = math.floor(lamb/t)
			if (((t0 * k0) + (t1 * k1)) != lamb):
				print(lamb)
				print(t0, t1, k0, k1)
				print((t0 * k0) + (t1 * k1))
				print("FAIL!")
				exit()
			temp.append(str(t0))															# t0 size
			temp.append(str(t1))															# t1 size
			temp.append(str(k0))															# k0 size
			temp.append(str(k1))															# k1 size
			temp.append(str(sk_size))														# sk size
			temp.append(str(pk_size))														# pk size

			sig_size = ((ell + (2*lamb) + B) * (t - 1)) + (lamb + B) + (ell + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128
			lower_bound = ((0 + (2*lamb) + B) * (t - 1)) + (lamb + B) + (0 + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128

			temp.append(str(int(sig_size/8)))
			temp.append(str(int(lower_bound/8)))
			table.append(temp)

	empty = []
	table.append(empty)

print("MQ OWF")
print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))


print("\n\n\n\n")


# # AIM
# aim_lambda_name = [1,3,5]
# aim_lambda = [128, 192, 256]
# aim_non_linear = [2, 2, 3]
# tau = [[8,9,10,11,12,13,14,15,16,17,18],[12,13,14,15,16,17,18,19,20,21,22,23,24,25,26],[17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36]] # # tau for each lambda
# table = [['scheme','ell','tau','tau_0','tau_1','k_0','k_1','sk','pk','sig size','lower bound']]

# for lambname, lamb, nonlin, lamb_tau in zip(aim_lambda_name, aim_lambda, aim_non_linear, tau):

# 	# here comes the sk, pk and ell size
# 	witness = nonlin*int(lamb/8)
# 	key = int(lamb/8)

# 	sk_size = int(lamb/8)
# 	pk_size = int(lamb/8)*2
# 	ell = (witness + key)*8

# 	for t in lamb_tau:
# 		temp = []

# 		# here comes the siganture size and the lower bound
# 		temp.append("FAEST-AIM-L" + str(lambname) + "_" + str(t)) 		# scheme name
# 		temp.append(str(ell))															# final ell length
# 		temp.append(str(t))																# tau size
# 		t0 = lamb%t
# 		t1 = t - t0
# 		k0 = math.ceil(lamb/t)
# 		k1 = math.floor(lamb/t)
# 		if (((t0 * k0) + (t1 * k1)) != lamb):
# 			print(lamb)
# 			print(t0, t1, k0, k1)
# 			print((t0 * k0) + (t1 * k1))
# 			print("FAIL!")
# 			exit()
# 		temp.append(str(t0))															# t0 size
# 		temp.append(str(t1))															# t1 size
# 		temp.append(str(k0))															# k0 size
# 		temp.append(str(k1))															# k1 size
# 		temp.append(str(sk_size))														# sk size
# 		temp.append(str(pk_size))														# pk size

# 		sig_size = ((ell + (2*lamb) + B) * (t - 1)) + (lamb + B) + (ell + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128
# 		lower_bound = ((0 + (2*lamb) + B) * (t - 1)) + (lamb + B) + (0 + lamb) + ((lamb * lamb) + (2 * lamb * t)) + lamb + 128

# 		temp.append(str(int(sig_size/8)))
# 		temp.append(str(int(lower_bound/8)))
# 		table.append(temp)

# 	empty = []
# 	table.append(empty)

# print("AIM OWF")
# print(tabulate(table, headers='firstrow', tablefmt='fancy_grid'))