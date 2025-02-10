If we can inject into the DOM, we can alter what the user sees or even potentially take actions as the user, effectively impersonating them! This became a significantly larger problem with modern web application frameworks or so-called single-page web applications where control over the DOM does not just mean control over a single webpage but persistence across the entire web application.

With the rise of modern frontend frameworks, birth was given to a new web application model called the single page application (SPA). SPAs are loaded only once when the user visits the website for the first time, and all code is loaded in the DOM. Leveraging JavaScript, instead of reloading the DOM with each new request made, the DOM is automatically updated.

Instead of reloading the DOM with each request, the responses only contain the data required to update the DOM. This drastically reduces the amount of overhead with each request and while the initial load of the web application may take longer, it is much more responsive when being used.

Modern frontend frameworks such as Angular, React, and Vue allow developers to create these SPAs. Instead of the web server being responsible for the DOM as well, the SPA is loaded once and then interfaces with the web server through API requests. While this increases the responsiveness of the web application, it can lead to interesting misconfigurations and vulnerabilities. The two most common are discussed below.

## Mistakes
- The first common mistake is confusing where the security boundary sits. There is a common saying in application security that states: "Client-side controls are only for the user experience; all security controls must be implemented server-side". This is important because a threat actor can control everything in the browser and, thus, can be bypassed.
	
	Not understanding this principle most commonly leads to authorization bypasses. An example of this is when the developers disabled the "edit" button in JavaScript. However, since you can alter the DOM in your browser, you can re-enable the button and make the request, thus leading to an authorization bypass. While it creates a better user experience to have the button disabled, a server-side security check is still needed to ensure that the user making the request has the relevant permissions to perform the edit action.


- The second common mistake is not sufficiently validating user input. This often happens when the frontend and backend development teams do not communicate who is taking responsibility for certain security controls. The frontend team will often implement filters to sanitise or validate user input before it is sent in a request to the web server. However, as mentioned before, threat actors can bypass frontend controls. Therefore, the frontend team should ensure that the backend team performs the same input validation and sanitisation when data is sent in requests. However, because the backend team usually does not know exactly how the frontend works, they are more likely to send raw, unsanitized and unfiltered data to the frontend in responses, expecting the frontend team to perform the sanitisation on the data before displaying it in the application.
	
	This can often lead to no team taking responsibility for input validation. As each team expects the other team to deal with security, it can often create security gaps, allowing for attacks such as Cross-Site Scripting (XSS) or Cross-Site Request Forgery (CSRF). This problem is compounded in the modern age, where most applications no longer work in isolation but are heavily integrated with other applications and systems. While unsanitised data injected into Application A may be harmless to Application A, the developers of Application B may incorrectly assume that this data has been sanitised, leading to a vulnerability in Application B through data sent via Application A.

## Attacks
It was mentioned that client-side security controls are only for the user experience. However, with the rise of modern frontend framework applications, this rule no longer holds true. Ignoring client-side security controls is exactly what leads to DOM-based attacks.

### **The Blind Server-Side**
While there are many different DOM-based attacks, all of them can be summarized by insufficiently validating and sanitizing user input before using it in JavaScript, which will alter the DOM. In modern web applications, developers will implement functions that alter the DOM without making any new requests to the web server or API. For example:

- A user clicks on a tab in the navigation pane. As the data on this tab has already been loaded through API requests, the user is navigated to the new tab by altering the DOM to set which tab is visible.
- A user filters the results shown in the table. As all results have already been loaded, through JavaScript the existing dataset is reduced and reloaded into the DOM to be displayed to the user.

In these examples and many other actions, no requests are made to the API, as there is no need to refresh the data being shown to the user. However, this leads to an interesting issue. What would protect us now if all of our security controls for data validation and sanitisation were implemented server-side? Therefore, with the rise of modern web applications, client-side security controls have become a lot more important.

### **The Source and the Sink**
As mentioned before, all DOM-based attacks start with untrusted user input making its way to JavaScript that modifies the DOM. To simplify the detection of these issues, we refer to them as sources and sinks. A source is the location where untrusted data is provided by the user to a JavaScript function, and the sink is the location where the data is used in JavaScript to update the DOM. If there is no sanitisation or validation performed on the data between the source and sink, it can lead to a DOM-based attack. Let's reuse the two examples above to define the sources and sinks:

|                                            |                                                                                                                                           |                                                                                                                                                                     |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Example**                                | **Source**                                                                                                                                | **Sink**                                                                                                                                                            |
| User clicking a tab on the navigation pane | When the user clicks the new tab, a developer may update the URL with a #tabname2 to indicate the tab that the user currently has active. | A JavaScript function executes on the event that the URL has been updated, recovers the updated tab information, and displays the correct tab.                      |
| User filtering the results of a table      | The input provided in a textbox by the user is used to filter the results.                                                                | A JavaScript function executes on the event that the information within the textbox updates and uses the information provided in the textbox to filter the dataset. |
The first example is quite interesting. Even though the initial user input was a mouse click, this was translated by the developers in an update to the URL. Using the # operator in the URL is common practice and is referred to as a fragment. Have you ever read a blog post, decided to send the URL to a friend, and when they opened the link, it opened at exactly the point you were reading? This occurs because JavaScript code updates the # portion of the URL as you are reading the article to indicate the heading closest to where you are in the article. When you send the URL, this information is also sent, and once the blog post is loaded, JavaScript recovers this information and automatically scrolls the page to your location. In our example, if you were to send the link to someone, once they opened it, they would view the same tab as you did when creating the link. While this is great for the user experience, it could lead to DOM-based attacks without proper validation of the data injected into the URL. With this in mind, let's look at a DOM-based attack example.

## **DOM-based Open Redirection**
Let's say that the frontend developers are using information from the # value to determine the location of navigation for the web application. This can lead to a DOM-based open redirect. Let's take a look at an example of this in JavaScript code:

```
goto = location.hash.slice(1) if (goto.startsWith('https:')) {   location = goto; }
```

The source in this example is the `location.hash.slice(1)` parameter which will take the first # element in the URL. Without sanitisation, this value is directly set in the `location` of the DOM, which is the sink. We can construct the following URL to exploit the issue:

```
https://realwebsite.com/#https://attacker.com
```

Once the DOM loads, the JavaScript will recover the # value of https://attacker.com and perform a redirect to our malicious website. This is quite a tame example. While there are other examples as well, the one we care about is DOM-based XSS.

There are other types of DOM-based attacks, but the principle for all of these remain the same where user input is used directly in a JavaScript element without sanitisation or validation, allow threat actors to control a part of the DOM.

There are other types of DOM-based attacks, but the principle for all of these remain the same where user input is used directly in a JavaScript element without sanitisation or validation, allow threat actors to control a part of the DOM.