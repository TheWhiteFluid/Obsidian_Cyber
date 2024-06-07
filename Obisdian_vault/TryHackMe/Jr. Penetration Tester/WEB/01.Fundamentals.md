
**OSSTMM**: https://www.isecom.org/OSSTMM.3.pdf
![[Pasted image 20240523113921.png]]

| **Stage**             | **Description**                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Information Gathering | This stage involves collecting as much publically accessible information about a target/organisation as possible, for example, OSINT and research.<br><br>**Note:** This does not involve scanning any systems.                                                                                                                                                                  |
| Enumeration/Scanning  | This stage involves discovering applications and services running on the systems. For example, finding a web server that may be potentially vulnerable.                                                                                                                                                                                                                          |
| Exploitation          | This stage involves leveraging vulnerabilities discovered on a system or application. This stage can involve the use of public exploits or exploiting application logic.                                                                                                                                                                                                         |
| Privilege Escalation  | Once you have successfully exploited a system or application (known as a foothold), this stage is the attempt to expand your access to a system. You can escalate horizontally and vertically, where horizontally is accessing another account of the same permission group (i.e. another user), whereas vertically is that of another permission group (i.e. an administrator). |
| Post-exploitation     | This stage involves a few sub-stages:  <br><br>**1.** What other hosts can be targeted (pivoting)<br><br>**2.** What additional information can we gather from the host now that we are a privileged user<br><br>**3.**  Covering your tracks<br><br>**4.** Reporting                                                                                                            |

**OWASP**: https://owasp.org/
![[Pasted image 20240523114052.png]]

**NIST**: https://www.nist.gov/cyberframework
![[Pasted image 20240523114426.png]]

**NCSC CAF**: https://www.ncsc.gov.uk/collection/cyber-assessment-framework/caf-objective-a-managing-security-risk
![[Pasted image 20240523114659.png]]