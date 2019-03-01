# Windows Privilege Escalation Techniques

> Subtitle or Short Description Goes Here

> ideally one sentence

> include terms/tags that can be searched


***Linux & Windows local privilege escalation methods tree***

[![Linux & Windows privilege escalation](https://raw.githubusercontent.com/chmodx/WinNixPE-workshop/master/media/lpe-tree.jpeg)]()


## Table of Contents

> If you're `README` has a lot of info, section headers might be nice.

- [Kernel](#kernel)
- [Features](#features)
- [Contributing](#contributing)
- [Team](#team)
- [FAQ](#faq)
- [Support](#support)
- [License](#license)


## Kernel

[![Windows architecture](https://raw.githubusercontent.com/chmodx/WinNixPE-workshop/master/media/windows-architecture.png)]()

> As shown in the above diagram, the Windows operating system has two main components: user mode and kernel mode, refer <a href="https://en.wikipedia.org/wiki/Architecture_of_Windows_NT" target="_blank">here</a>.

> **HACK AWAY!** 🔨🔨🔨 

#### **#1 Step | 🔎 Information Gathering**
	
- **Option 1** 🔪 Get `systeminfo` and use `windows-exploit-suggester` which based upon the hotfix data.

    - Execute `systeminfo` on the target machine then copy and save on the attacker machine.
     - Use [windows-exploit-suggester](#windows-exploit-suggester):
    	- First, update the tool then we get file in the `XLS` format.
    	- Using this `XLS` file and system information execute the tool and observe potential exploits list.
    	
## windows-exploit-suggester
> This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins. It requires the 'systeminfo' command output from a Windows host in order to compare that the Microsoft security bulletin database and determine the patch level of the host, refer <a href="https://github.com/GDSSecurity/Windows-Exploit-Suggester" target="_blank">here</a>.

```shell
$  ./windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2019-02-28-mssb.xls
[*] done
```

```shell
$ ./windows-exploit-suggester.py --database 2019-02-28-mssb.xls --systeminfo systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 2 hotfix(es) against the 386 potential bulletins(s) with a database of 137 known exploits
[*] there are now 386 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 7 SP1 64-bit'
[*]
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
....
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*]
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
```


- **Option 2** 🔪 Use PowerShell script [Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1){:target="_blank"} to find missing software patches for privilege escalation.

	- 👯 Clone this repo to your local (attacker) machine using `https://github.com/rasta-mouse/Sherlock`
     - Transfer the `Sherlock.ps1` PowerShell script to the target machine. [How transfer file to target machine ?](link)
     -  After, execute the script on the target machine with spesial flag as shown below.
     ```cmd
     powershell.exe -nop -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"
     ```

```cmd
C:\Users\user>powershell.exe -nop -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"
...

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Appears Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

```

#### **#2 Step | 🎯 Exploit**
#####❗️ We can download exploit via [searchploit](https://www.exploit-db.com/searchsploit){:target="_blank"} tool then compile this or use compiled exploit from the [here](https://github.com/SecWiki/windows-kernel-exploits){:target="_blank"}. 
---





---

## FAQ

- **How do I do *specifically* so and so?**
    - No problem! Just do this.

---

## Support

Reach out to me at one of the following places!

- Website at <a href="http://fvcproductions.com" target="_blank">`fvcproductions.com`</a>
- Twitter at <a href="http://twitter.com/fvcproductions" target="_blank">`@fvcproductions`</a>
- Insert more social links here.

---

## Donations (Optional)

- You could include a <a href="https://cdn.rawgit.com/gratipay/gratipay-badge/2.3.0/dist/gratipay.png" target="_blank">Gratipay</a> link as well.

[![Support via Gratipay](https://cdn.rawgit.com/gratipay/gratipay-badge/2.3.0/dist/gratipay.png)](https://gratipay.com/fvcproductions/)


---

## License

[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Copyright 2015 © <a href="http://fvcproductions.com" target="_blank">FVCproductions</a>.