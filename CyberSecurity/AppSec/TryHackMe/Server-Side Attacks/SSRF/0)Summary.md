SSRF is a web application security vulnerability that allows the attacker to force the server to make **unauthorised requests to any local or external source** on behalf of the web server. SSRF **allows an attacker to interact with internal systems**, potentially leading to data leaks, service disruption, or even remote code execution.

When developing networked software, it's common to make requests to external servers. Developers often use these requests to **fetch remote resources** like software updates or import data from other applications. While these requests are typically safe, **improper implementation can lead to a vulnerability known as SSRF**.
	![](Pasted%20image%2020250117155338.png)
An SSRF vulnerability can arise when user-provided data is used to construct a request, such as forming a URL. To execute an SSRF attack, **an attacker can manipulate a parameter value within the vulnerable software**, effectively creating or controlling requests from that software and directing them towards other servers or even the same server.

SSRF vulnerabilities can be found in various types of computer software across a wide range of programming languages and platforms as long as the software operates in a networked environment. While most SSRF vulnerabilities are commonly discovered in web applications and other networked software, they can also be present in server software.

**OWASP Ranking**
SSRF is a formidable security threat, earning a spot in [OWASP's top 10 list](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/), making it imperative to understand and defend against it as it jeopardises data integrity and application security. As per OWASP, factors regarding SSRF are mentioned below:

|   |   |   |   |   |   |   |
|---|---|---|---|---|---|---|
|**Max Incidence Rate**|**Avg Incidence Rate  <br>**|**Avg Weighted Exploit**|**Avg Weighted Impact  <br>**|**Max Coverage  <br>**|**Total Occurrences  <br>**|**Total CVEs**|
|2.72%|2.72%|8.28|6.72|67.2%|9503|385|

The above table provides insights into the **prevalence, impact, and coverage** of an SSRF vulnerability in a specific context or dataset that OWASP measures. The interpretation of the above table is explained below:
- **Max Incidence Rate**: It suggests how often this vulnerability has been encountered relative to other vulnerabilities in OWASP.
- **Avg Incidence Rate**: It shows how common this vulnerability is compared to others.
- **Avg Weighted Exploit**: Indicate the average difficulty or effort required to exploit an SSRF vulnerability.
- **Avg Weighted Impact**: Average potential impact or severity of exploiting an SSRF vulnerability.
- **Max Coverage**: It indicates how much of the systems have been exploited due to this vulnerability.
- **Total Occurrences**: Total exploitations due to this vulnerability that OWASP has analysed.
- **Total CVEs**: Total CVEs about SSRF. These are CVE-2021-21311, CVE-2018-11759 and CVE-2017-9506. This data of OWASP is from 2021.

# Risk of SSRF  
- **Data Exposure**
As explained earlier, cybercriminals can gain unauthorised access by tampering with requests on behalf of the vulnerable web application to gain access to sensitive data hosted in the internal network.
- **Reconnaissance**
An attacker can carry out port scanning of internal networks by running malicious scripts on vulnerable servers or redirecting to scripts hosted on some external server.
- **Denial of Service**
It is a common scenario that internal networks or servers do not expect many requests; therefore, they are configured to handle low bandwidth. Attackers can flood the servers with multiple illegitimate requests, causing them to remain unavailable to handle genuine requests.

