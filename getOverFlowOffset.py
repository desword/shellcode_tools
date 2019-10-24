
import commands
import os
import sys
import subprocess
import re

from pygdbmi.gdbcontroller import GdbController

# The rough steps.
# 1. get the return address. We need to provide the retun address. in the vuladdress.
# 2. using gdb to set breakpoints at the return address.
# 3. generate the patternoffset files, and read the files to print into the program.
# 4. run the program using gdb until the breakpoints.
# 5. print the EBP value and calculate the offset using pattern offset.

def usage():
    print "[+] Usage: python getOverFlowOffset.py [vul_ret_address] [vul_program]"
    print "[+] Hints: you give me vul_ret_address, I give you the offset :)"
    print "[*] Example: python getOverFlowOffset.py 0x080484BD example_bin/xdctf15-pwn200"


def print_log(response):
	for each in response:
		try:
			print "[%s]\t%s\t%s" % (each['type'], each['message'], each['payload']) 
			# return [each['type'], each['message'], each['payload']]
		except:
			pass


def parse_response(response, typeList):
	parse_results = []
	for each in response:
		try:
			if each['type'] in typeList:
				parse_results.append( (each['type'], each['payload']) )
		except:
			pass
	return parse_results


def find_real_vulret_address():
	global ret_address

	# search the usable functions. 
	op = commands.getstatusoutput("strings  %s" % (target_program))
	# print op
	leakAddrFunc = "" # used for lead the real address.
	tmp1 = op[1].split('\n')
	# print tmp1
	for eachStr in tmp1:
		if eachStr in funcListOut:
			leakAddrFunc = eachStr
			break;
	if leakAddrFunc == "":# perform func search using in-like.
		for eachStr in tmp1:
			if eachStr in funcListIn:
				leakAddrFunc = eachStr
				break;
	if leakAddrFunc == "":
		print "[-] No leak functions can be used. Can not leak the real address."
		exit(1)
	print "[*] Found a leak function: %s" % leakAddrFunc


	gdbmi = GdbController()
	response = gdbmi.write('-file-exec-file %s' % (target_program))
	response = gdbmi.write('file %s' % (target_program))

	response = gdbmi.write('break %s' % (leakAddrFunc))
	# print_log(response)

	response = gdbmi.write('run')
	# print_log(response)

	response = gdbmi.write('finish')
	# print_log(response)

	i=0;
	maxi = 10;
	badStr = ["<", "?"]
	realAddress = ""
	while True:
		if programBits == 32:
			response = gdbmi.write('print $eip')
			response = gdbmi.write('print $eip')
		elif programBits == 64:
			response = gdbmi.write('print $rip')
			response = gdbmi.write('print $rip')
		# print_log(response)

		typeList =["console"]
		results = parse_response(response, typeList)
		# print results



		traget_str = results[0][1]
		isOkToLeave = 1
		for eachBad in badStr:
			if traget_str.find(eachBad) != -1:
				isOkToLeave = 0
				break;
		if isOkToLeave == 1: # now we found the real address and can leave.
			# print "[*] Found the real address, we can leave" 
			### extract the address from the result.
			m = re.search(r"0x([a-f0-9]+)", results[0][1])
			if m:
				# print "[*] address 0x%s" % (m.group(1)) 
				realAddress = m.group(1)
				print "[*] Found the leaked address 0x%s, we can leave" % (realAddress) 

			break;

		### not ok example. 
		# '$2 = (void (*)()) 0x7ffff7ddac42 <open_verify+130>'
		### ok example, 
		# $2 = (void (*)()) 0x555555554739

		response = gdbmi.write('finish')


	### now we can compus the real vul_ret_address.
	ret_address = "0x" + realAddress[:-3] + ret_address[-3:]
	print "[*] The real vul_ret_address is:%s" % (ret_address)

### list of functions for combating with program enabling PIE.
funcListIn = ['read', 'gets', 'scanf']
funcListOut = ['puts', 'write', 'printf']




try:
    ret_address = sys.argv[1]
    target_program = sys.argv[2]
except:
    usage()
    exit(1)


# ret_address = "0x080484BD"
# target_program = "example_bin/xdctf15-pwn200"
# ret_address = "0x00632"
# target_program = "example_bin/pwn200_PIE"
# target_program = "example_bin/pwn200_PIE_64bits"


pattern_len = 700
pattern_file_name = "passwd"

programBits = 0
enablePIE = 0


### check program is 32bits or 64 bits.
op = commands.getstatusoutput("file  %s" % (target_program))
# print op
tmp1 = op[1].split(':')[1]
tmp2 = tmp1.split(' ')[2]
tmp3 = tmp2.split('-')[0]
print "[*] %s is %s bits" % (target_program, tmp3)
programBits = int(tmp3)


### [old way]check whether enable PIE. We now only check the ret_address to infer whether enabling PIE.
# smallInt_check = 0xfff
# addre_to_int = int(ret_address, 16)
# if addre_to_int < smallInt_check:
# 	enablePIE=1
# 	print "[*] PIE is enabled"
# else:
# 	enablePIE=0
# 	print "[*] no PIE"

### check whether enable PIE. classic way. PIE program is .so, while non-PIE is executable.
op = commands.getstatusoutput("readelf -h %s | grep Type" % (target_program))
# print op
if op[1].find("Shared object file") != -1:
	print "[*] PIE is enabled"
	enablePIE = 1
elif op[1].find("Executable file") != -1:
	print "[*] no PIE"
	enablePIE = 0


### if PIE is enabled, we first infer the real vul_ret_address.
if enablePIE == 1:
	find_real_vulret_address()


op = commands.getstatusoutput("python patternLocOffset.py -l %d -f %s -c" % (pattern_len, pattern_file_name))

# Start gdb process
gdbmi = GdbController()
# print(gdbmi.get_subprocess_cmd())  # print actual command run as subprocess

response = gdbmi.write('-file-exec-file %s' % (target_program))
# print_log(response)

response = gdbmi.write('break *%s' % (ret_address))
# print_log(response)

response = gdbmi.write('run < %s' % (pattern_file_name))
# print_log(response)

response = gdbmi.write('print $ebp')
# print_log(response)

over_write_str = ""
for eachResp in response:
	try:
		eachResp['payload'].index("$1")
		over_write_str = eachResp['payload'].split(" ")[-1]
	except:
		pass

# transform the offset into hex.
if over_write_str.find('0x') == -1:
	over_write_str = hex(int(over_write_str))

# finally, to find the offset to the EBP.
op = commands.getstatusoutput("python patternLocOffset.py -l %d -s %s" % (pattern_len, over_write_str))
op_str = op[1]
# print_log(op)

op = commands.getstatusoutput("rm %s" % (pattern_file_name))


offset_find = -1
m = re.search(r'offset \d+', op_str)
if m is not None:
	offset_find = int(m.group().split(" ")[-1])
else:
	print "[-] No matches. Check the return address."
	exit(1)

print "[+] Found offset to the EBP is %d." % (offset_find)
print "[+] THe offset to the RET_ADDR is %d (32bits) or %d (64bits)." % (offset_find + 4, offset_find + 8)




