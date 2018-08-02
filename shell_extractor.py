#!/usr/bin/env python
#####################################################################################
## extract shellcode binarys for c or python
## Tested against Ubuntu 12.04 & Windows # #
##
## Example:
# $ python shell_extractor.py execve c
# char shellcode[] = {
# "\x24\x06\x06\x66"
# "\x04\xd0\xff\xff"
# "\x28\x06\xff\xff"
# "\x27\xbd\xff\xe0"
# "\x27\xe4\x10\x01"
# "\x24\x84\xf0\x1f"
# "\xaf\xa4\xff\xe8"
# "\xaf\xa0\xff\xec"
# "\x27\xa5\xff\xe8"
# "\x24\x02\x0f\xab"
# "\x00\x00\x00\x0c"
# "\x2f\x62\x69\x6e"
# "\x2f\x73\x68\x00"
# };
## desword # 2018-8-2
#####################################################################################



import os
import sys

def ExtractOffset(line):    
    sp = line.split(' ')
    while '' in sp:
        sp.remove('')
    # print sp

    try:
        section = sp[2]
    except:
        section = -1
    try:
        offset = int(sp[5], 16)
    except:
        offset = -1
    try:
        size = int(sp[6], 16)
    except:
        size = -1
    return [section, offset, size]

def usage():
    print "[+] Usage: python shell_extractor.py [filename] [format]"
    print "[*] Where format can be c or py"
    


try:
    fileName = sys.argv[1]
    printformat = sys.argv[2]
except:
    usage()
    exit(1)


extractionCmd = "readelf -S " + fileName


result = os.popen(extractionCmd)
res = result.read()
lines = res.splitlines()

section = 0; offset = 0; size = 0;

for line in lines:
    [section, offset, size] = ExtractOffset(line)
    if section == ".text":
        # print line
        # print "find, offset", offset, "size", size
        break;



f = open(fileName,"rb")
outfile = []
i = 0
while 1:
    c = f.read(1)
    i = i + 1
    if not c:
        break
    if ord(c) <= 15:
        outfile.append("0x0"+hex(ord(c))[2:])
    else:
        outfile.append(hex(ord(c)))

f.close()


### extract shell code

extracted = outfile[offset:offset+size]



### print for  shellcode book.

if printformat == "py":
    shellOutput = ["shellcode = \"\""]
    shellHeader = "shellcode +="
    for i in range(0, len(extracted), 4):
        shelltmp = ""
        for eachByte in extracted[i:i+4]:
            shelltmp += ("\\x" + eachByte[2:])
        shellOutput.append("%s \"%s\"" % (shellHeader, shelltmp))

    shellOutputStr = "\n".join(shellOutput)
    print shellOutputStr
elif printformat == "c":

    ### print for c source code test

    shellOutput = ["char shellcode[] = {"]
    for i in range(0, len(extracted), 4):
        shelltmp = ""
        for eachByte in extracted[i:i+4]:
            shelltmp += ("\\x" + eachByte[2:])
        shellOutput.append("\"%s\"" % (shelltmp))
    shellOutput.append("};")

    shellOutputStr = "\n".join(shellOutput)
    print shellOutputStr



