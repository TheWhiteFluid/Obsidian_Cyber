Privilege escalation is a journey. There are no silver bullets, and much depends on the specific configuration of the target system. The kernel version, installed applications, supported programming languages, other users' passwords are a few key elements that will affect your road to the root shell.  

This new skill will be an essential part of your arsenal whether you are participating in CTFs, taking certification exams, or working as a penetration tester.

**What does "privilege escalation" mean?**
At it's core, Privilege Escalation usually involves going from a lower permission account to a higher permission one. More technically, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.  
  
It's rare when performing a real-world penetration test to be able to gain a foothold (initial access) that gives you direct administrative access. Privilege escalation is crucial because it lets you gain system administrator levels of access, which allows you to perform actions such as:
- Resetting passwords;  
- Bypassing access controls to compromise protected data;
- Editing software configurations;
- Enabling persistence;
- Changing the privilege of existing (or new) users;
- Execute any administrative command;
  
## **Enumeration**
Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.

### **hostname**
The `hostname` command will return the hostname of the target machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).

	![[Pasted image 20240821161939.png]]
### **uname -a**
Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.
	![[Pasted image 20240821162011.png]]
### **/proc/version**
The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.

Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.
	![[Pasted image 20240821171940.png]]
### **/etc/issue**
Systems can also be identified by looking at the `/etc/issue` file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.

	![[Pasted image 20240821172132.png]]
### **ps** 
The `ps` command is an effective way to see the running processes on a Linux system. Typing `ps` on your terminal will show processes for the current shell.

	![[Pasted image 20240821172211.png]]
The output of the `ps` (Process Status) will show the following;
- **PID**: The process ID (unique to the process)
- **TTY**: Terminal type used by the user
- **Time**: Amount of CPU time used by the process (this is NOT the time this process has been running for)
- **CMD**: The command or executable running (will NOT display any command line parameter)

The “ps” command provides a few useful options.
- `ps -A`: View all running processes
- `ps aux`: The `aux` option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.
- `ps axjf`: View process tree (see the tree formation until `ps axjf` is run below)
	![[Pasted image 20240821044152.png]]

### **env**
The `env` command will show environmental variables.
The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.
	![[Pasted image 20240821044338.png]]

### **sudo -l**
The target system may be configured to allow users to run some (or all) commands with root privileges. The `sudo -l` command can be used to list all commands your user can run using `sudo`.

### **ls**
While looking for potential privilege escalation vectors, please remember to always use the `ls` command with the `-la` parameter. The example below shows how the “secret.txt” file can easily be missed using the `ls` or `ls -l` commands.
	![[Pasted image 20240821172404.png]]

### **Id**
The `id` command will provide a general overview of the user’s privilege level and group memberships. It is worth remembering that the `id` command can also be used to obtain the same information for another user as seen below.
	![[Pasted image 20240821172449.png]]

### **/etc/passwd**
Reading the `/etc/passwd` file can be an easy way to discover users on the system.
	![[Pasted image 20240821172526.png]]
	![[Pasted image 20240821172546.png]]

*Note:*
	Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to `grep` for “home” as real users will most likely have their folders under the “home” directory.
	
	![[Pasted image 20240821172635.png]]

### **history**
Looking at earlier commands with the `history` command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames

### **ifconfig**
The target system may be a pivoting point to another network. The `ifconfig` command will give us information about the network interfaces of the system. The example below shows the target system has three interfaces (eth0, tun0, and tun1). Our attacking machine can reach the eth0 interface but can not directly access the two other networks.

This can be confirmed using the `ip route` command to see which network routes exist.
	![[Pasted image 20240821172821.png]]

### **netstat**
Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The `netstat` command can be used with several different options to gather information on existing connections.
- `netstat -a`: shows all listening ports and established connections.
- `netstat -at` or `netstat -au` can also be used to list TCP or UDP protocols respectively.
- `netstat -l`: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)
	  ![[Pasted image 20240821172902.png]]
	  
- `netstat -s`: list network usage statistics by protocol (below) This can also be used with the `-t` or `-u` options to limit the output to a specific protocol.
		![[Pasted image 20240821172957.png]]
		
- `netstat -tp`: list connections with the service name and PID information.
		![[Pasted image 20240821173041.png]]
		This can also be used with the `-l` option to list listening ports (below)![[Pasted image 20240821173116.png]]
		
- `netstat -i`: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.
		  ![[Pasted image 20240821173151.png]]

The `netstat` usage you will probably see most often in blog posts, write-ups, and courses is `netstat -ano` which could be broken down as follows;
- `-a`: Display all sockets
- `-n`: Do not resolve names
- `-o`: Display timers
	![[Pasted image 20240821173356.png]]

### **find** 
Searching the target system for important information and potential privilege escalation vectors can be fruitful.

**Find files:**
- `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
- `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
- `find / -type d -name config`: find the directory named config under “/”
- `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
- `find / -perm a=x`: find executable files
- `find /home -user frank`: find all files for user “frank” under “/home”
- `find / -mtime 10`: find files that were modified in the last 10 days
- `find / -atime 10`: find files that were accessed in the last 10 day
- `find / -cmin -60`: find files changed within the last hour (60 minutes)
- `find / -amin -60`: find files accesses within the last hour (60 minutes)
- `find / -size 50M`: find files with a 50 MB size

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with `-type f 2>/dev/null` to redirect errors to “/dev/null” and have a cleaner output (below).
	![[Pasted image 20240821173637.png]]

Folders and files that can be written to or executed from:
- `find / -writable -type d 2>/dev/null` : Find world-writeable folders
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders

Find development tools and supported languages:
- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

Find specific file permissions:
- `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

### locate
The `locate` command is used to quickly find the locations of files on your system.

- **How it works:** `locate` searches through a database of file paths that is created by the `updatedb` command. This database contains a snapshot of your filesystem, allowing `locate` to find files much faster than using a command like `find`, which searches the filesystem directly.

    `locate filename`
    
    This will return a list of paths that match the provided filename.

### grep
The `grep` command is used to search text or files for lines that match a specified pattern.

- **How it works:** `grep` searches through the content of files line by line, matching each line against the pattern you provide.

    `grep "pattern" filename`
    
    This will print all lines in `filename` that contain the `pattern`.
    
- **Example:**
    `grep "error" /var/log/syslog`
    
    This will search for the word "error" in the system log file.
    
- **Common options:**
    - `-i`: Ignore case (case-insensitive search).
    - `-r`: Recursively search directories.
    - `-n`: Show line numbers where matches are found.
    - `-v`: Invert the match, showing lines that do not match the pattern.

### **cut**
The `cut` command is used to extract specific sections from each line of a file or stream of text.

- **How it works:** `cut` can split each line into fields based on a delimiter (e.g., a space or comma) and then extract one or more fields from each line.
    `cut -d "delimiter" -f field_number filename`
    
    - `-d "delimiter"` specifies the delimiter used to separate fields.
    - `-f field_number` specifies which field(s) to extract.
- **Example:**
    `cut -d ":" -f 1 /etc/passwd`
    
    This will extract the first field from each line in `/etc/passwd`, where fields are separated by colons (`:`). In this case, it will display usernames.
    
- **Common options:**
    - `-b`: Extract specific bytes.
    - `-c`: Extract specific characters.
    - `-f`: Extract specific fields based on a delimiter.

### **sort**
The `sort` command is used to sort lines of text files or input streams.

- **How it works:** `sort` reads input line by line, compares them, and then outputs the lines in sorted order. The default is to sort alphabetically, but it can also sort numerically, by month, etc.

    `sort filename`
    
    This will sort the lines in `filename` alphabetically.
    
    `sort numbers.txt`
    
    This will sort the contents of `numbers.txt` in ascending order.
    
- **Common options:**
    - `-r`: Reverse the sort order (descending).
    - `-n`: Sort numerically.
    - `-k`: Sort by a specific key (column).
    - `-t`: Specify a field delimiter for sorting.


## **Automated Enumeration Tools**
Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
	
	![[Pasted image 20240821235212.png]]
	
	![[Pasted image 20240821235246.png]]

	![[Pasted image 20240821235323.png]]

## **Privilege Escalation: Kernel Exploits**
Privilege escalation ideally leads to root privileges. This can sometimes be achieved simply by exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access.

Unless a single vulnerability leads to a root shell, the privilege escalation process will rely on misconfigurations and lax permissions.

The kernel on Linux systems manages the communication between components such as the memory on the system and applications. This critical function requires the kernel to have specific privileges; thus, a successful exploit will potentially lead to root privileges.

The Kernel exploit methodology is simple;
1. Identify the kernel version;
2. Search and find an exploit code for the kernel version of the target system;
3. Run the exploit;

*Note:*
	Please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit.

*Hints:*
1. Being too specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit
2. Be sure you understand how the exploit code works BEFORE you launch it. Some exploit codes can make changes on the operating system that would make them unsecured in further use or make irreversible changes to the system, creating problems later. Of course, these may not be great concerns within a lab or CTF environment, but these are absolute no-nos during a real penetration testing engagement.
3. Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
4. You can transfer the exploit code from your machine to the target system using the `SimpleHTTPServer` Python module and `wget` respectively.

Q) Find and use the appropriate kernel exploit to gain root privileges on the target system.
	![[Pasted image 20240822021207.png]]\

Q)What is the content of the flag1.txt file?
	![[Pasted image 20240822021346.png]]
	![[Pasted image 20240822021411.png]]
	
To pull the exploit code into the target file via wget, send it to `/tmp`, since it can run on the exploit file you want there.
	![[Pasted image 20240822021519.png]]

Now we will try to run this code using the command  `gcc exploit.c -o exploit`

If you have a simple C program like this in `exploit.c`:
```
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

Running the command `gcc exploit.c -o exploit` will create an executable named `exploit`. 

You can then run it with: `./exploit`

	![[Pasted image 20240822021619.png]]
	![[Pasted image 20240822021646.png]]

## **Privilege Escalation: Sudo**
The sudo command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system. Any user can check its current situation related to root privileges using the `sudo -l` command.

[https://gtfobins.github.io/](https://gtfobins.github.io/) is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.