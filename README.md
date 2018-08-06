# shellcode_tools
useful tools for writing shellcode 


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
