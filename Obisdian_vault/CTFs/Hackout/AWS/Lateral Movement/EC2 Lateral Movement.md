
 **AWS IAM Roles**: If you have permission to assume roles, you can use these roles to move laterally between instances. Use the `aws sts assume-role` command to assume a role and then use the temporary credentials to access other resources.
 **SSM (Simple Systems Manager)**: If SSM is enabled, you can use it to run commands on other instances without needing direct SSH or RDP access. Use the `aws ssm send-command` command to execute commands on remote instances.
**CloudWatch Logs**: If CloudWatch Logs is enabled, you can use it to gather information about other instances and potentially move laterally by exploiting misconfigurations or weak credentials.
**Network-based Lateral Movement**:
    - **SSH**: Use SSH to move between Linux instances.
    - **RDP**: Use RDP to move between Windows instances.
    - **WinRM**: If WinRM is enabled, you can use it to run commands on remote Windows instances.
 **AWS Security Groups**: Enumerate security groups to find open ports and services that can be used for lateral movement.


## Tools
 **Chaos Monkey**:
    - **Description**: A tool to simulate failures and test the resilience of your AWS infrastructure.
    - **GitHub**: [Chaos Monkey](https://github.com/Netflix/chaosmonkey)  
      
**AWS-Audit**:
    - **Description**: A tool for auditing AWS accounts and services for security vulnerabilities.
    - **GitHub**: [AWS-Audit](https://github.com/nccgroup/AWS-Audit)


Steps:
- obtinerea unui aws account key / key compromise (github dorking sau stocare ei intr-un note.txt ascuns in masina compromisa) // scanning tools
  ![](Pasted%20image%2020241107212200.png)
- creearea unui user nou (IAM) --> give acces to CLI
  ![](Pasted%20image%2020241107212426.png)
- folosirea diferitor comenzi/tooluri de enumerare a instantelor/s3 bucket urilor/etc
  https://github.com/eon01/AWS-CheatSheet?tab=readme-ov-file
  
- lateral movement pe VPC-uri 
	  - relay ul sa fie o instanta EC2 aflata intr-un VPC (public/private subnet)
	  - team serverul sa fie o alta instanta EC2 aflata intr-un VPC separat (private)
	![](Pasted%20image%2020241107211720.png)
	