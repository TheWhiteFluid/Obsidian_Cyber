- port scanning phase:
	nmap -sC -sV -p- {IP}![](Pasted%20image%2020241206130150.png)
![](Pasted%20image%2020241206131016.png)

- inspect source page
![](Pasted%20image%2020241206131028.png)

- dir enumeration phase
```
gobuster dir --url http://10.10.208.169:1337/hmr_ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -p pattern.txt (hmr_{GOBUSTER})
```
![](Pasted%20image%2020241206145639.png)

- logs dir check
	![](Pasted%20image%2020241206145719.png)
	![](Pasted%20image%2020241206145732.png)
- email address found: tester@hammer.thm
	![](Pasted%20image%2020241206145934.png)
		![](Pasted%20image%2020241206150228.png)

![](Pasted%20image%2020241206151052.png)