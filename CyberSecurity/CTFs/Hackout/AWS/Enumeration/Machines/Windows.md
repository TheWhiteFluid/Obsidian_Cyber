
1. **Cloud-specific Services**:
    - **AWS**: Check for the presence of the AWS SSM Agent service (`AmazonSSMAgent`).
        - Example command: `Get-Service -Name AmazonSSMAgent`
    - **Azure**: Check for the presence of the Azure VM Agent service (`WaaSMgmtSvc`).
        - Example command: `Get-Service -Name WaaSMgmtSvc`
    - **GCP**: Check for the presence of the Google Compute Engine VM service.
        - Example command: `Get-Service -Name gceguestagent`
2. **Registry Keys**:
    - **AWS**: Check for registry keys related to the AWS SSM Agent.
        - Example command: `reg query HKLM\SOFTWARE\Amazon\SSMAgent`
    - **Azure**: Check for registry keys related to the Azure VM Agent.
        - Example command: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AzureVM`
3. **Network Interfaces**:
    - Check for cloud-specific network interfaces.
    - Example command: `Get-NetAdapter`

4. **WMIC**:
    - Use WMIC to enumerate processes and services.
    - Example commands:
        - `wmic process list brief`


```
wmic csproduct get name,uuid
```
This command retrieves the system name and UUID, which can sometimes be unique to cloud instances.

```
wmic service get name,displayname,state
```
This command lists all running services. Cloud-specific services like AWS SSM Agent or Azure VM Agent might be present.

```
wmic process get name,processid,commandline
```
This command lists all running processes. Look for cloud-specific processes like `AmazonSSMAgent` for AWS or `WaaSMgmtSvc` for Azure.