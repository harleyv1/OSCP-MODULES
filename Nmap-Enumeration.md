## Use Cases :
> The tool is one of the most used tools by network administrators and IT security specialists. It is used to:

- Audit the security aspects of networks
- Simulate penetration tests
- Check firewall and IDS settings and configurations
- Types of possible connections
- Network mapping
- Response analysis
- Identify open ports
- Vulnerability assessment as well.

## Nmap Architecture :
> Nmap offers many different types of scans that can be used to obtain various results about our targets. Basically, Nmap can be divided into the following scanning techniques:

- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

#### Tcpdump: 

```shell
Pwn1Sec@htb[/htb]$ sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28

tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
```

#### Nc :

```shell
Pwn1Sec@htb[/htb]$  nc -nv 10.129.2.28 25

Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)
```

#### Tcpdump - Intercepted Traffic:

```shell\
18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 331260178 ecr 0,sackOK,eol], length 0
18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234, win 65160, options [mss 1460,sackOK,TS val 1800383922 ecr 331260178,nop,wscale 7], length 0
18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058, options [nop,nop,TS val 331260304 ecr 1800383922], length 0
18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510, options [nop,nop,TS val 1800383985 ecr 331260304], length 35: SMTP: 220 inlane ESMTP Postfix (Ubuntu)
18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058, options [nop,nop,TS val 331260368 ecr 1800383985], length 0
```

> The first three lines show us the three-way handshake.

1.)[SYN]  `18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], <SNIP>`
2.)[SYN-ACK]  `18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], <SNIP>`
3.)[ACK] `18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], <SNIP>`

---
## Nmap Scripting Engine :
---
+ Nmap Scripting Engine (`NSE`) is another handy feature of `Nmap`. It provides us with the possibility to create scripts in Lua for interaction with certain services. There are a total of 14 categories into which these scripts can be divided:

|**Category**|**Description**|
|---|---|
|`auth`|Determination of authentication credentials.|
|`broadcast`|Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans.|
|`brute`|Executes scripts that try to log in to the respective service by brute-forcing with credentials.|
|`default`|Default scripts executed by using the `-sC` option.|
|`discovery`|Evaluation of accessible services.|
|`dos`|These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.|
|`exploit`|This category of scripts tries to exploit known vulnerabilities for the scanned port.|
|`external`|Scripts that use external services for further processing.|
|`fuzzer`|This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.|
|`intrusive`|Intrusive scripts that could negatively affect the target system.|
|`malware`|Checks if some malware infects the target system.|
|`safe`|Defensive scripts that do not perform intrusive and destructive access.|
|`version`|Extension for service detection.|
|`vuln`|Identification of specific vulnerabilities.|

- We have several ways to define the desired scripts in `Nmap`.
---
## Timing
> Because such settings cannot always be optimized manually, as in a black-box penetration test, `Nmap` offers six different timing templates (`-T <0-5>`) for us to use. These values (`0-5`) determine the aggressiveness of our scans. This can also have negative effects if the scan is too aggressive, and security systems may block us due to the produced network traffic. The default timing template used when we have defined nothing else is the normal (`-T 3`).

- `-T 0` / `-T paranoid`
- `-T 1` / `-T sneaky`
- `-T 2` / `-T polite`
- `-T 3` / `-T normal`
- `-T 4` / `-T aggressive`
- `-T 5` / `-T insane`

## IDS/IPS

- Like the firewall, the intrusion detection system (`IDS`) and intrusion prevention system (`IPS`) are also software-based components. `IDS` scans the network for potential attacks, analyzes them, and reports any detected attacks. `IPS` complements `IDS` by taking specific defensive measures if a potential attack should have been detected. The analysis of such attacks is based on pattern matching and signatures. If specific patterns are detected, such as a service detection scan, `IPS` may prevent the pending connection attempts.

## DNS Proxying

- By default, `Nmap` performs a reverse DNS resolution unless otherwise specified to find more important information about our target. These DNS queries are also passed in most cases because the given web server is supposed to be found and visited. The DNS queries are made over the `UDP port 53`. The `TCP port 53` was previously only used for the so-called "`Zone transfers`" between the DNS servers or data transfer larger than 512 bytes. More and more, this is changing due to IPv6 and DNSSEC expansions. These changes cause many DNS requests to be made via TCP port 53.

- However, `Nmap` still gives us a way to specify DNS servers ourselves (`--dns-server <ns>,<ns>`). This method could be fundamental to us if we are in a demilitarized zone (`DMZ`). The company's DNS servers are usually more trusted than those from the Internet. So, for example, we could use them to interact with the hosts of the internal network. As another example, we can use `TCP port 53` as a source port (`--source-port`) for our scans. If the administrator uses the firewall to control this port and does not filter IDS/IPS properly, our TCP packets will be trusted and passed through.

#### SYN-Scan of a Filtered Port :

```shell
Pwn1Sec@htb[/htb]$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 22:50 CEST
SENT (0.0417s) TCP 10.10.14.2:33436 > 10.129.2.28:50000 S ttl=41 id=21939 iplen=44  seq=736533153 win=1024 <mss 1460>
SENT (1.0481s) TCP 10.10.14.2:33437 > 10.129.2.28:50000 S ttl=46 id=6446 iplen=44  seq=736598688 win=1024 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up.

PORT      STATE    SERVICE
50000/tcp filtered ibm-db2

Nmap done: 1 IP address (1 host up) scanned in 2.06 seconds
```

#### SYN-Scan From DNS Port :

```shell
Pwn1Sec@htb[/htb]$ sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
Nmap scan report for 10.129.2.28
Host is up (0.013s latency).

PORT      STATE SERVICE
50000/tcp open  ibm-db2
MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

#### Connect To The Filtered Port :

```shell
Pwn1Sec@htb[/htb]$ ncat -nv --source-port 53 10.129.2.28 50000

Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.2.28:50000.
220 ProFTPd
```

## Scanning Options

| **Nmap Option** | **Description** |
|---|----|
| `10.10.10.0/24` | Target network range. |
| `-sn` | Disables port scanning. |
| `-Pn` | Disables ICMP Echo Requests |
| `-n` | Disables DNS Resolution. |
| `-PE` | Performs the ping scan by using ICMP Echo Requests against the target. |
| `--packet-trace` | Shows all packets sent and received. |
| `--reason` | Displays the reason for a specific result. |
| `--disable-arp-ping` | Disables ARP Ping Requests. |
| `--top-ports=<num>` | Scans the specified top ports that have been defined as most frequent.  |
| `-p-` | Scan all ports. |
| `-p22-110` | Scan all ports between 22 and 110. |
| `-p22,25` | Scans only the specified ports 22 and 25. |
| `-F` | Scans top 100 ports. |
| `-sS` | Performs an TCP SYN-Scan. |
| `-sA` | Performs an TCP ACK-Scan. |
| `-sU` | Performs an UDP Scan. |
| `-sV` | Scans the discovered services for their versions. |
| `-sC` | Perform a Script Scan with scripts that are categorized as "default". |
| `--script <script>` | Performs a Script Scan by using the specified scripts. |
| `-O` | Performs an OS Detection Scan to determine the OS of the target. |
| `-A` | Performs OS Detection, Service Detection, and traceroute scans. |
| `-D RND:5` | Sets the number of random Decoys that will be used to scan the target. |
| `-e` | Specifies the network interface that is used for the scan. |
| `-S 10.10.10.200` | Specifies the source IP address for the scan. |
| `-g` | Specifies the source port for the scan. |
| `--dns-server <ns>` | DNS resolution is performed by using a specified name server. |
## Output Options
| **Nmap Option** | **Description** |
|---|----|
| `-oA filename` | Stores the results in all available formats starting with the name of "filename". |
| `-oN filename` | Stores the results in normal format with the name "filename". |
| `-oG filename` | Stores the results in "grepable" format with the name of "filename". |
| `-oX filename` | Stores the results in XML format with the name of "filename". |
## Performance Options

| **Nmap Option** | **Description** |
|---|----|
| `--max-retries <num>` | Sets the number of retries for scans of specific ports. |
| `--stats-every=5s` | Displays scan's status every 5 seconds. |
| `-v/-vv` | Displays verbose output during the scan. |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout. |
| `--max-rtt-timeout 100ms` | Sets the specified time value as maximum RTT timeout. |
| `--min-rate 300` | Sets the number of packets that will be sent simultaneously. |
| `-T <0-5>` | Specifies the specific timing template. |