## **==Map/Technologies==**
-  https://github.com/Ignitetechnologies/Mindmap

## **OWASP Cheat Sheet**
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#alternative-using-a-double-submit-cookie-pattern

## **==RECON // OSINT==**
-  https://dnsdumpster.com/ (DNS)
-  https://www.shodan.io/ (DNS and more)
- https://github.com/six2dez/reconftw (reconftw)
- https://github.com/blacklanternsecurity/bbot (bbot)
- https://github.com/michenriksen/aquatone (auquatone)
  
- https://github.com/sullo/nikto (nikto - vuln scan)
- https://github.com/projectdiscovery/nuclei (nuclei - vuln scan)  
  
-  https://haveibeenpwned.com/ (databreach - find email)
- https://www.dehashed.com/ (leaked personal data)
- https://intelx.io/ (inteligenceX)
- https://leakix.net/ (leakix)
## ==**Frameworks**==
-  https://owasp.org/ (OWASP)
	 - [https://wiki.owasp.org/index.php/OWASP_favicon_database](https://wiki.owasp.org/index.php/OWASP_favicon_database)
	 - https://owasp.org/www-project-secure-headers
	 - https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html
-  https://www.nist.gov/cyberframework (NIST)
-  https://www.itgovernance.co.uk/iso27001_pen_testing (ISO27001)

## **==Tools==**
- https://pentestmonkey.net/ (pentest cheatsheet)
-  https://github.com/es3n1n/no-defender/blob/master/README.md (Windows Defender breaker via WSC API)
- https://www.monkey.org/~dugsong/fragroute/ (Packets Fragmentation)
- [CyberChef](https://icyberchef.com/) (Escaped Unicodes) 
- https://github.com/sc0tfree/updog (FILE TRANSFER // PYTHON SERVER)  
- https://github.com/kgretzky/pwndrop (FILE HOSTING SERVICE)    
### **Payloads**
 https://github.com/cyberheartmi9/PayloadsAllTheThings 
 https://github.com/payloadbox
  
### **Hashes**
-  https://crackstation.net (online)
  - https://www.kali.org/tools/hashcat/ (offline)
    
### **Brute Force**
-  https://github.com/vanhauser-thc/thc-hydra (Dictionary Password Attacks)
-  https://github.com/mandatoryprogrammer/xsshunter-express (Blind XSS attacks)
-  https://github.com/danielmiessler/SecLists (Bruteforce attack)
  
### **MITM**
-  [Ettercap](https://www.ettercap-project.org/) and [Bettercap](https://www.bettercap.org/). (MITM)
  
### ==**WEB**==
[JWT.io](https://jwt.io/) (JWT token decoder)
#### **Injections**
-  https://github.com/payloadbox/command-injection-payload-list/blob/master/README.md 
- https://github.com/sqlmapproject/sqlmap (SQLMap - automated tool for sql injections)
- https://github.com/djalilayed/tryhackme/blob/main/NoSQLInjection/Extracting_Users_Passwords.py (NoSQL - password guessing automating script - regex)

#### **XSS**
- http://www.xss-payloads.com (XSS payloads)
#### **XXE**
- https://github.com/GoSecure/dtd-finder
#### **LFI(local file inclusion)**
- https://github.com/D35m0nd142/LFISuite
- https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
  
#### ==Reverse Shell==
-  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md (Reverse Shell Cheat Sheet)
-  https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet (Reverse Shell)
-  https://github.com/danielmiessler/SecLists. (Wordlists & Shells)
- https://www.revshells.com/ (Reverse Shell Generator)
  - https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx (rWebShell using ASP.NET)
    
- https://github.com/JohnHammond/poor-mans-pentest (shell STABILIZATION)    

## **==PrivEscalation==**
### **Linux:**
https://gtfobins.github.io/
- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)  (!!!)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) (!!!)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

### **Windows**
- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
- [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
- [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
- [Decoder's Blog](https://decoder.cloud/)
- [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
- [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- https://github.com/PowerShellMafia
  
  -  [Priv2Admin](https://github.com/gtworek/Priv2Admin)

- WinPEAS (https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) (detectable)
- PrivescCheck (https://github.com/itm4n/PrivescCheck) (detectable)
- WES-NG: Windows Exploit Suggester - Next Generation (https://github.com/bitsadmin/wesng) (not-detectable)
- Metasploit (`multi/recon/local_exploit_suggester` module)

## **==APIs==**
- https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c
- https://www.postman.com/
- https://swagger.io/
- https://www.soapui.org/
  
## ==Active Directory==
- https://github.com/wavestone-cdt/powerpxe (PXE boot images) 
- https://github.com/GhostPack/Seatbelt (enumeration)
- https://github.com/nicocha30/ligolo-ng (port forwarding/tunneling)
- [Sshuttle](https://github.com/sshuttle/sshuttle) (l.movement)
- [Rpivot](https://github.com/klsecservices/rpivot) (l.movement)
- [Chisel](https://github.com/jpillora/chisel) (l.movement)
- [ForgeCert](https://github.com/GhostPack/ForgeCert) (persistance - certificates forging)
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) (persistance -  patch LSASS to update SID history)
- [Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) (cracking group policy passwords)
- [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) (LAPS machine enum.)
- [Snaffler](https://github.com/SnaffCon/Snaffler) (enum.)
- [Seatbelt](https://github.com/GhostPack/Seatbelt) (enum.)
- [Lazagne](https://www.hackingarticles.in/post-exploitation-on-saved-password-with-lazagne/) (enum.)


## **==AWS // Cloud==**
- https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/ (CheatSheet !!!)
- https://github.com/salesforce/cloudsplaining (privesc)
- https://github.com/eon01/AWS-CheatSheet?tab=readme-ov-file
- https://prowler.com/blog/prowler-5/ (prowler)
- https://securitycafe.ro/2024/11/19/azure-cloudquarry-searching-for-secrets-in-public-vm-images/ (Azure CloudQuarry)

## **==RedTeam==**
https://github.com/bigb0sss/RedTeam-OffensiveSecurity/tree/master/01-CobaltStrike (Cobalt Strike)
### Malware Detection
1. www.virustotal.com
2. www.hybrid-analysis.com
3. www.threatminer.com
4. www.threatcrowd.com
5. www.robtext.com

