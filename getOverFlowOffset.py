
import commands
import os
import sys
import subprocess
import re

from pygdbmi.gdbcontroller import GdbController



# to automatically extract the offset to the EBP.
# requirements: 1. gdb-gef. 2. patternLocOffset.py  3. pygdbmi



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


try:
    ret_address = sys.argv[1]
    # print ret_address
    target_program = sys.argv[2]
    # print target_program
except:
    usage()
    exit(1)




# ret_address = "0x080484BD"
# target_program = "xdctf15-pwn200"

pattern_len = 700
pattern_file_name = "passwd"


op = commands.getstatusoutput("python patternLocOffset.py -l %d -f %s -c" % (pattern_len, pattern_file_name))


# Start gdb process
gdbmi = GdbController()
# print(gdbmi.get_subprocess_cmd())  # print actual command run as subprocess

response = gdbmi.write('-file-exec-file %s' % (target_program))
# print(response)

response = gdbmi.write('break *%s' % (ret_address))
# print(response)

response = gdbmi.write('run < %s' % (pattern_file_name))
# print(response)

response = gdbmi.write('print $ebp')
# print(response)

over_write_str = ""
for eachResp in response:
	try:
		eachResp['payload'].index("$1")
		# print eachResp['payload'].split(" ")
		over_write_str = eachResp['payload'].split(" ")[-1]
		# print over_write_str
	except:
		pass

# finally, to find the offset to the EBP.
op = commands.getstatusoutput("python patternLocOffset.py -l %d -s %s" % (pattern_len, over_write_str))
op_str = op[1]
# print op_str

op = commands.getstatusoutput("rm %s" % (pattern_file_name))


offset_find = -1
m = re.search(r'offset \d+', op_str)
if m is not None:
	offset_find = int(m.group().split(" ")[-1])
	# print offset_find
	# print m.group().split(" ") 
else:
	print "[-] No matches. Check the return address."
	exit(1)

print "[+] Found offset to the EBP is %d." % (offset_find)
print "[+] THe offset to the RET_ADDR is %d (32bits) or %d (64bits)." % (offset_find + 4, offset_find + 8)
# op_list = op[1].split("\n")



# print op[1].split("\n")



# op = commands.getstatusoutput("gdb %s;b *%s" % (target_program, ret_address))
# print op[1]



# op = commands.getstatusoutput("quit")



