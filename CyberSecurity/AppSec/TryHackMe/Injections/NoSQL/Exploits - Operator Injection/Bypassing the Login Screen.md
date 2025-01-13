First of all, let's open the website on [http://10.10.110.21/](http://machine_ip/) and send an incorrect user/pass to capture the request on Burp:
	![](Pasted%20image%2020241215141405.png)
The original captured login request looks like this:
	![](Pasted%20image%2020241215141431.png)
We now proceed to intercept another login request and modify the user and pass variables to send the desired arrays:
	![](Pasted%20image%2020241215141500.png)
This forces the database to return all user documents and as a result we are finally logged into the application:
	![](Pasted%20image%2020241215141531.png)
