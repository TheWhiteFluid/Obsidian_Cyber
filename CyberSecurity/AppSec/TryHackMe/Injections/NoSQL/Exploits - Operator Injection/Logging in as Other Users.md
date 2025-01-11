We have managed to bypass the application's login screen, but with the former technique, we can only login as the first user returned by the database. By making use of the `$nin` operator, we are going to modify our payload so that we can control which user we want to obtain.

First, the `$nin` operator allows us to create a filter by specifying criteria where the desired documents have some field, not in a list of values. So if we want to log in as any user except for the user admin, we could modify our payload to look like this:
	![](Pasted%20image%2020241215142019.png)
This would translate to a filter that has the following structure:
	`['username'=>['$nin'=>['admin'] ], 'password'=>['$ne'=>'aweasdf']]`

Which tells the database to return any user for whom the username isn't admin and the password isn't aweasdf. As a result, we are now granted access to another user's account.

Notice that the $nin operator receives a list of values to ignore. We can continue to expand the list by adjusting our payload as follows:
	![](Pasted%20image%2020241215142145.png)
This would result in a filter like this:  
	`['username'=>['$nin'=>['admin', 'jude'] ], 'password'=>['$ne'=>'aweasdf']]`

This can be repeated as many times as needed until we gain access to all of the available accounts.