At this point, we have access to all of the accounts in the application. However, it is important to try to extract the actual passwords in use as they might be reused in other services. To accomplish this, we will be abusing the $regex operator to ask a series of questions to the server that allow us to recover the passwords via a process that resembles playing the game hangman.

First, let's take one of the users discovered before and try to guess the length of his password. We will be using the following payload to do that:
	![](Pasted%20image%2020241215143818.png)
Notice that we are asking the database if there is a user with a username of admin and a password that matches the regex: `**^.{7}$**`. This basically represents a wildcard word of length 7. Since the server responds with a login error, we know the password length for the user admin isn't 7. After some trial and error, we finally arrived at the correct answer:
	![](Pasted%20image%2020241215143906.png)
We now know the password for user admin has length 5. Now to figure out the actual content, we modify our payload as follows:
	![](Pasted%20image%2020241215143945.png)
We are now working with a regex of length 5 (a single letter c plus 4 dots), matching the discovered password length, and asking if the admin's password matches the regex `^c....$`, which means it starts with a lowercase c, followed by any 4 characters. Since the server response is an invalid login, we now know the first letter of the password can't be "c". We continue iterating over all available characters until we get a successful response from the server:
	![](Pasted%20image%2020241215144019.png)
This confirms that the first letter of admin's password is 'a'. The same process can be repeated for the other letters until the full password is recovered. This can be repeated for other users as well if needed.

script for automating nosql users passwords:
https://github.com/djalilayed/tryhackme/blob/main/NoSQLInjection/Extracting_Users_Passwords.py
