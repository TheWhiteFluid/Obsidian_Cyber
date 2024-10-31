
1. **AWS CLI**: The AWS Command Line Interface (CLI) is a powerful tool for enumerating permissions and managing AWS resources. You can use commands like `aws iam get-policy-version` and `aws iam list-attached-role-policies` to enumerate IAM policies and roles.
2. **IAM Access Analyzer**: This tool helps you identify resources in your organization and accounts that are shared with an external entity. It can be used to enumerate permissions and identify potential security risks.
    
3. **Pacu**: Pacu is a tool that automates the process of enumerating and exploiting AWS environments. It can help you identify misconfigurations and enumerate permissions across various AWS services.
   - **GitHub**: [Pacu](https://github.com/RhinoSecurityLabs/pacu)
     
4. **Enum4linux**: While primarily used for Windows enumeration, Enum4linux can also be used to gather information about AWS IAM roles and policies if the target instance has SMB shares exposed.
   - **GitHub**: [Enum4linux](https://github.com/cisco/enum4linux)
   
5. **CloudMapper**:
    - **Description**: A tool to visualize your AWS environment, including VPCs, subnets, and security groups.
    - **GitHub**: [CloudMapper](https://github.com/dualspark/cloudmapper)