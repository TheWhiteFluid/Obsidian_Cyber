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
	Grafana is running bt default on port 3000 -> v.8.2.5
	
Q) What is the ID of the severe CVE that affects this version of Grafana?
	CVE-2021-43798

Q) If this server was publicly available, What site might have information on its services already?
	shodan

Q) How would we search the site "example.com" for pdf files, using advanced Google search tags?
	`site:example.com filetype:pdf`