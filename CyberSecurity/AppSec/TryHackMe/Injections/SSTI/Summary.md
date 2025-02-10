Server-Side Template Injection (SSTI) is a vulnerability that occurs when user input is unsafely incorporated into a server-side template, allowing attackers to inject and execute arbitrary code on the server. Template engines are commonly used in web applications to generate dynamic HTML by combining fixed templates with dynamic data. When these engines process user input without proper sanitization, they become susceptible to SSTI attacks.

**Core Concepts of SSTI**
- **Dynamic Content Generation:** Template engines replace placeholders with actual data, allowing applications to generate dynamic HTML pages. This process can be exploited if user inputs are not properly sanitized.
- **User Input as Template Code:** When user inputs are treated as part of the template code, they can introduce harmful logic into the rendered output, leading to SSTI.

The core of SSTI lies in the improper handling of user input within server-side templates. Template engines interpret and execute embedded expressions to generate dynamic content. If an attacker can inject malicious payloads into these expressions, they can manipulate the server-side logic and potentially execute arbitrary code.
	![](Pasted%20image%2020250106043417.png)

When user input is directly embedded in templates without proper validation or escaping, attackers can craft payloads that alter the template's behaviour. This can lead to various unintended server-side actions, including:

- Reading or modifying server-side files.
- Executing system commands.
- Accessing sensitive information (e.g., environment variables, database credentials).

## Template Engines
A template engine is like a machine that helps build web pages dynamically. Template engines offer various functionalities that speed up the development process but can also introduce risks. Most template engines allow expressions to be used for simple calculations or logic operations within templates.

A template engine works similarly:
1. **Template**: The engine uses a pre-designed template with placeholders like {{ name }} for dynamic content.
2. **User Input**: The engine receives user input (like a name, age, or message) and stores it in a variable.
3. **Combination**: The engine combines the template with the user input, replacing the placeholders with the actual data.
4. **Output**: The engine generates a final, dynamic web page with the user's input inserted into the template.

In the context of SSTI, the template engine's ability to execute code is what makes it vulnerable to attacks. If user input is not properly sanitized, an attacker can inject malicious code, which the template engine will execute, leading to unintended consequences.

### Common Template Engines
Template engines are an integral part of modern web development, allowing developers to generate dynamic HTML content by combining templates with data. Here are some of the most commonly used template engines:

- **Jinja2**: Highly popular in Python applications, known for its expressiveness and powerful rendering capabilities.
- **Twig**: The default template engine for Symfony in PHP, Twig offers a robust environment with secure default settings.
- **Pug/Jade**: Known for its minimal and clean HTML templating syntax, Pug/Jade is popular among Node.js developers.

Template engines work by parsing template files, which contain static content mixed with special syntax for dynamic content. When rendering a template, the engine replaces the dynamic parts with actual data provided at runtime. For example:
```python
from jinja2 import Template

hello_template = Template("Hello, {{ name }}!")
output = hello_template.render(name="World")
print(output)
```

### Determining the Template Engine
Different template engines have distinct syntaxes and features, making them vulnerable to SSTI in various ways. Here are some examples of vulnerable template syntaxes:

#### **Jinja2/Twig**
Jinja2 and Twig are similar in syntax and behavior, making them somewhat challenging to distinguish from each other just by payload responses. However, you can detect their presence by testing their expression-handling capabilities. For example, using the vulnerable VM, if you use the payload {{7*'7'}} in Twig, the output would be **49**.
	![](Pasted%20image%2020250106044030.png)

However, if you use the same payload in an application that uses Jinja2, the output would be **7777777**:
	![](Pasted%20image%2020250106044052.png)

#### **Jade/Pug**
Pug, formerly known as Jade, uses a different syntax for handling expressions, which can be exploited to identify its usage. Pug/Jade evaluates JavaScript expressions within `#{}`. For example, using the payload #{7*7} would return 49.
	![](Pasted%20image%2020250106044128.png)

Unlike Jinja2 or Twig, Pug/Jade directly allows JavaScript execution within its templates without the need for additional delimiters like {{ }}. For example:
	![](Pasted%20image%2020250106044159.png)

