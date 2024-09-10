
st = ['0x01','0x02','0x04','0x08','0x10','0x20','0x40','0x80']


lamb = 256
block_size = 32

out = "{\n"
str_idx = 1
for i in range(lamb):
	i = i + 1
	if i == lamb:
		break
	out = out + "{"
	for by in range(block_size):
		if by == int(i/8) and by != block_size-1:
			out = out + st[str_idx%8] + ", "
		elif by == int(i/8) and by == block_size-1:
			out = out + st[str_idx%8]
		elif by == block_size-1:
			out = out + "0x00"
		else:
			out = out + "0x00, "
	out = out + "},\n"
	str_idx = str_idx + 1

out = out + "}"

print(out)
