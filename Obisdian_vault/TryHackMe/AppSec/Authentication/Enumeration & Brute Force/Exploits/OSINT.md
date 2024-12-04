Digging into a web application’s past can be as revealing as examining its present:

## Wayback URLs
Think of the Internet Archive's Wayback Machine ([https://archive.org/web/](https://archive.org/web/)) as a time machine. It lets you travel back and explore older versions of websites, uncovering files and directories that are no longer visible but might still linger on the server. These relics can sometimes provide a backdoor right into the present system.

For example, using TryHackMe as a target, we can see all of the website's past versions from 2018 to the present.
	![](Pasted%20image%2020241127003304.png)
To dump all of the links that are saved in Wayback Machine, we can use the tool called waybackurls. Hosted in [GitHub](https://github.com/tomnomnom/waybackurls), we can easily install this on our machine by using the below commands:
```shell-session
user@tryhackme $ git clone https://github.com/tomnomnom/waybackurls
user@tryhackme $ cd waybackurls
user@tryhackme $ sudo apt install golang-go -y # This command is optional
user@tryhackme $ go build
user@tryhackme $ ls -lah
total 6.6M
drwxr-xr-x 4 user user 4.0K Jul  1 18:20 .
drwxr-xr-x 9 user user 4.0K Jul  1 18:20 ..
drwxr-xr-x 8 user user 4.0K Jul  1 18:20 .git
-rw-r--r-- 1 user user   36 Jul  1 18:20 .gitignore
-rw-r--r-- 1 user user  454 Jul  1 18:20 README.mkd
-rw-r--r-- 1 user user   49 Jul  1 18:20 go.mod
-rw-r--r-- 1 user user 5.4K Jul  1 18:20 main.go
drwxr-xr-x 2 user user 4.0K Jul  1 18:20 script
-rwxr-xr-x 1 user user 6.5M Jul  1 18:20 waybackurls
user@tryhackme $ ./waybackurls tryhackme.com
[-- snip --]
https://tryhackme.com/.well-known/ai-plugin.json
https://tryhackme.com/.well-known/assetlinks.json
https://tryhackme.com/.well-known/dnt-policy.txt
https://tryhackme.com/.well-known/gpc.json
https://tryhackme.com/.well-known/nodeinfo
https://tryhackme.com/.well-known/openid-configuration
https://tryhackme.com/.well-known/security.txt
https://tryhackme.com/.well-known/trust.txt
[-- snip --]
```

## Google Dorks  
This is where your savvy with search engines shines. By crafting specific search queries, known as Google Dorks, you can find information that wasn’t meant to be public. These queries can pull up everything from exposed administrative directories to logs containing passwords and indices of sensitive directories. For example:

- To find administrative panels: `site:example.com inurl:admin`
- To unearth log files with passwords: `filetype:log "password" site:example.com`
- To discover backup directories: `intitle:"index of" "backup" site:example.com`