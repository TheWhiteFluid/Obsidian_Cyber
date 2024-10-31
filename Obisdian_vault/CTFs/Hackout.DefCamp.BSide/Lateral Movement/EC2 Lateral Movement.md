
1. **AWS IAM Roles**: If you have permission to assume roles, you can use these roles to move laterally between instances. Use the `aws sts assume-role` command to assume a role and then use the temporary credentials to access other resources.
2. **SSM (Simple Systems Manager)**: If SSM is enabled, you can use it to run commands on other instances without needing direct SSH or RDP access. Use the `aws ssm send-command` command to execute commands on remote instances.
3. **CloudWatch Logs**: If CloudWatch Logs is enabled, you can use it to gather information about other instances and potentially move laterally by exploiting misconfigurations or weak credentials.
4. **Network-based Lateral Movement**:
    - **SSH**: Use SSH to move between Linux instances.
    - **RDP**: Use RDP to move between Windows instances.
    - **WinRM**: If WinRM is enabled, you can use it to run commands on remote Windows instances.
5. **AWS Security Groups**: Enumerate security groups to find open ports and services that can be used for lateral movement.


## Tools
5. **Chaos Monkey**:
    - **Description**: A tool to simulate failures and test the resilience of your AWS infrastructure.
    - **GitHub**: [Chaos Monkey](https://github.com/Netflix/chaosmonkey)
      
6. **AWS Systems Manager (SSM)**:
    - **Description**: Allows you to remotely manage instances, automate operational tasks, and run commands securely.
    - **Documentation**: [AWS SSM](https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-systems-manager.html)
      
7. **AWS EC2 Instance Connect**:
    - **Description**: Allows you to connect to your instances without an SSH key or password.
    - **Documentation**: [EC2 Instance Connect](https://docs.aws.amazon.com/ec2/latest/userguide/ec2-instance-connect.html)
      
      
**AWS-Audit**:
    - **Description**: A tool for auditing AWS accounts and services for security vulnerabilities.
    - **GitHub**: [AWS-Audit](https://github.com/nccgroup/AWS-Audit)