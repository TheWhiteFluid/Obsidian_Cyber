1. **nikto** (server scan - outdated stuff)
	`nikto -h {url} -ssl`

	- Website screenshots: It automatically captures screenshots of web pages.
	- Concurrent scanning: Can scan multiple websites simultaneously for efficiency.
	- Chrome-based: Uses headless Chrome for rendering, ensuring accurate representation of modern web technologies.
	- Evidence gathering: Useful for documenting findings during security assessments.
	- Supports various inputs: Can take URLs, CIDR ranges, or Nmap output as input.
	- Report generation: Creates HTML reports of captured screenshots for easy review.
	- Customizable: Allows adjustments to timeout settings, resolution, and other parameters.

2. **owasp - zap** 
	`zaproxy`

	- Active and passive scanning: Performs both active (sending requests) and passive (observing traffic) vulnerability scans.
	- Intercepting proxy: Allows manual inspection and modification of web traffic.
	- Automated crawling: Discovers the structure of the target web application.
	- API scanning: Can test REST, GraphQL, and SOAP APIs.
	- Scripting support: Allows custom scripts for specialized testing.
	- Fuzzing: Includes a fuzzer for finding unexpected vulnerabilities.
	- Dynamic SSL certificates: Generates SSL certificates for HTTPS inspection.
	- Authentication handling: Supports various authentication mechanisms.
	- Browser integration: Can be used with Firefox and Chrome for manual testing.
	- Reporting: Generates detailed HTML reports of findings.
	- OWASP Top 10 coverage: Designed to detect vulnerabilities in the OWASP Top 10 list.
	- Extensibility: Supports add-ons for additional functionality.


3. **burpsuite** (check different extensions as retired.js beside automate scan)


4. **gowtiness** (screenshots of every site)
	`gowitness file -f {host.txt}`

	- Website screenshots: It automatically captures screenshots of web pages.
	- Concurrent scanning: Can scan multiple websites simultaneously for efficiency.
	- Chrome-based: Uses headless Chrome for rendering, ensuring accurate representation of modern web technologies.
	- Evidence gathering: Useful for documenting findings during security assessments.
	- Supports various inputs: Can take URLs, CIDR ranges, or Nmap output as input.
	- Report generation: Creates HTML reports of captured screenshots for easy review.
	- Customizable: Allows adjustments to timeout settings, resolution, and other parameters.


4. **Caido**
	- User-friendly interface: Designed with a modern, intuitive UI for ease of use.
	-  Web proxy: Intercepts and allows modification of web traffic.
	-  Automatic scanning: Performs automated vulnerability scans on web applications.
	-  Manual testing support: Provides tools for manual penetration testing.
	-  Collaborative features: Allows multiple testers to work on the same project simultaneously.
	-  API testing: Supports testing of REST and GraphQL APIs.
	-  Custom scripting: Enables users to write custom scripts for specialized tests.
	-  Integrated browser: Includes a built-in browser for seamless testing.
	-  Session handling: Manages complex authentication and session mechanisms.
	-  Reporting: Generates detailed reports of findings.
	-  Cross-platform: Available for Windows, macOS, and Linux.
	-  Performance focus: Emphasizes speed and efficiency in scanning and analysis.

Caido aims to combine the power of established tools like Burp Suite with a more modern, user-friendly approach. It's designed to be accessible to both experienced penetration testers and those newer to the field.

![[Pasted image 20241002182807.png]]
