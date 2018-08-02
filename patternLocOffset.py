#!/usr/bin/env python
#####################################################################################
## Create pattern strings & location offset 
## Tested against Ubuntu 12.04 & Windows # #
##
## Example:
## C:\Users\Lenov\Desktop> patterLocOffset.py -c -l 260 -f output.txt
### [*] Create pattern string contains 260 characters ok!
### [+] output to output.txt ok!
##
## C:\Users\Lenov\Desktop> patternLocOffset.py -s 0x41613141 -l 260
### [*] Create pattern string contains 260 characters ok!
### [*] Exact match at offset 3
#
## Nimdakey # 09-10-2013
#####################################################################################

import argparse
import struct
import binascii
import string
import time
import sys
import re

a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
b = "abcdefghijklmnopqrstuvwxyz"
c = "0123456789"

def generate(count,output):
    #
    # pattern create
    codeStr = ''
    print '[*] Create pattern string contains %d characters'%count,
    timeStart = time.time()
    for i in range(0,count):
        codeStr += a[i/(26*10)]+b[(i%(26*10))/10]+c[i%(26*10)%10]
    print 'ok!'
    if output:
        print '[+] output to %s'%output,
        fw = open(output,'w')
        fw.write(codeStr)
        fw.close() 
        print 'ok!'
    else:
        return codeStr
    print "[+] take time: %.4f s"%(time.time()-timeStart)
    
def patternMatch(searchCode, length=1024):
    #
    # pattern search
    offset = 0
    pattern = None

    timeStart = time.time()
    is0xHex = re.match('^0x[0-9a-fA-F]{8}',searchCode)
    isHex = re.match('^[0-9a-fA-F]{8}',searchCode)
    
    if is0xHex:
        #0x41613141
        pattern = binascii.a2b_hex(searchCode[2:])
    elif isHex:
        #41613141
        pattern = binascii.a2b_hex(searchCode)
    else:
        print '[-] seach Pattern eg:0x41613141'
        sys.exit(1)
        
    source = generate(length,None)
    offset = source.find(pattern)
    
    if offset != -1:
        print "[*] Exact match at offset %d"%offset
    else:
        print "[*] No exact matches, looking for likely candidates..."
        reverse = list(pattern)
        reverse.reverse()
        pattern = "".join(reverse)
        offset = source.find(pattern)
        if offset != -1:
            print "[+] Possible match at offset %d (adjusted another-endian)"%offset
    print "[+] take time: %.4f s"%(time.time()-timeStart)
    
def main():
    ## parse argument
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--search', help='search for pattern')
    parser.add_argument('-c', '--create', help='create a pattern',\
                        action='store_true')
    parser.add_argument('-f', '--file', help='output file name',\
                        default='patternShell.txt')
    parser.add_argument('-l', '--length',help='length of pattern code',\
                        type=int,default=1024)
    #parser.add_argument('-v', dest='verbose', action='store_true')
    args = parser.parse_args()

    ## save all argument
    length = args.length
    output = args.file
    #verbose = args.verbose
    createCode = args.create
    searchCode = args.search

    if createCode and (0 < args.length <= 26*26*10):
        #eg:  -c -l 90
        generate(length,output)
    elif searchCode and (0 < args.length <= 26*26*10):
        #eg: -s 0x474230141
        patternMatch(searchCode,length)
    else:
        print '[-] You shoud chices from [-c -s]'
        print '[-] Pattern length must be less than 6760'
        print 'more help: pattern.py -h'
    # ...

if __name__ == "__main__":
    main()
