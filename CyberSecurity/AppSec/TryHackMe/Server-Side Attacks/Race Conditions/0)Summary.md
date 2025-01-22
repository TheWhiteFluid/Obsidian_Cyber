Let’s say we are tasked with testing the security of an online shopping web application. Many questions pop up. Can we reuse a single $10 gift card to pay for a $100 item? Can we apply the same discount to our shopping cart multiple times? The answer is maybe! If the system is susceptible to a race condition vulnerability, we can do all this and more.

This room introduces the race conditions vulnerability. A race condition is a situation in computer programs where the timing of events influences the behaviour and outcome of the program. It typically happens when a variable gets accessed and modified by multiple threads. Due to a lack of proper lock mechanisms and synchronization between the different threads, an attacker might abuse the system and apply a discount multiple times or make money transactions beyond their balance.

## Multi-Threading
Let's have a quick overview of the following terms:
- **Program**
- **Process**
- **Thread**
- **Multi-threading**

### **Programs**
A **program** is a set of instructions to achieve a specific task. You need to execute the program to accomplish what you want. Unless you execute it, it won’t do anything and remains a set of static instructions. As example please see the following minimalistic Flask server.  

The code below dictates that the app will listen on port 8080 and respond with a minimal greeting HTML page that contains “Hello, World!” However, we must run these instructions (program) before we expect to get any greeting pages.
```python
# Import the Flask class from the flask module
from flask import Flask

# Create an instance of the Flask class representing the application
app = Flask(__name__)

# Define a route for the root URL ('/')
@app.route('/')
def hello_world():
    # This function will be executed when the root URL is accessed
    # It returns a string containing HTML code for a simple web page
    return '<html><head><title>Greeting</title></head><body><h1>Hello, World!</h1></body></html>'

# This checks if the script is being run directly (as the main program)
# and not being imported as a module
if __name__ == '__main__':
    # Run the Flask application
    # The host='0.0.0.0' allows the server to be accessible from any IP address
    # The port=8080 specifies the port number on which the server will listen
    app.run(host='0.0.0.0', port=8080)
```

### **Processes**
A **process** is a **_program_** in execution. In some literature, you might come across the term **job**. Both terms refer to the same thing, although the term process has superseded the term job. Unlike a program, which is static, a process is a dynamic entity. It holds several key aspects, in particular:
- **Program**: The executable code related to the process
- **Memory**: Temporary data storage
- **State**: A process usually hops between different states. After it is in the New state, i.e., just created, it moves to the Ready state, i.e., ready to run once given CPU time. Once the CPU allocates time for it, it goes to the Running state. Furthermore, it can be in the Waiting state pending I/O or event completion. Once it exits, it moves to the Terminated state.
	![](Pasted%20image%2020250122045514.png)
If you run the Flask code above, a process will be created, and it will listen for incoming connections at port 8080. In other words, it will spend most of its time in the Waiting state. When it receives an HTTP `GET /` request, it will switch to the Ready state, waiting for its turn to run based on the CPU scheduling. Once in the Running state, it sends the HTML page to the client and returns to the Waiting state.

From the server’s perspective, the app is servicing clients sequentially, i.e., client requests are processed one at a time. (Note that Flask is multi-threaded by default since version 1.0. We used the argument `--without-threads` to force it to run single-threaded.) _Please note that the Flask command shown below is for demonstrative purposes only._

```python
$ flask run --without-threads --host=0.0.0.0
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.0.104:5000
Press CTRL+C to quit
127.0.0.1 - - [16/Apr/2024 23:34:46] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [16/Apr/2024 23:34:48] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [16/Apr/2024 23:35:11] "GET / HTTP/1.1" 200 -
```

### **Threads**
Let’s wrap up with another coffee analogy! Consider the case of a commercial espresso machine in a coffee shop. Let’s say it has two portafilters. At the start of the work day, the barista turns on the espresso machine, and whenever a customer orders an espresso, one portafilter is used to prepare an espresso shot for them. Does another customer order an espresso? No problem, the second portafilter to the rescue! The warmed-up espresso machine is the process; each new order is assigned a portafilter; that’s the analogy for the thread.

*A thread is a lightweight unit of execution*. It shares various memory parts and instructions with the process. In many cases, we need to replicate the same process repeatedly. Think of a web server serving thousands of users the same page (or a personalized page). We can adopt one of two main approaches:
- *Serial*: One process is running; it serves one user after the other sequentially. New users are enqueued.
- *Parallel*: One process is running; it creates a thread to serve every new user. New users are only enqueued after the maximum number of running threads is reached.

The previous app can run with four threads using Gunicorn. Gunicorn, also called the “Green Unicorn”, is a **Python WSGI HTTP server**. WSGI stands for Web Server Gateway Interface, which bridges web servers and Python web applications. In particular, Gunicorn can spawn multiple worker processes to handle incoming requests simultaneously. By running `gunicorn` with the `--workers=4` option, we are specifying that we want four workers ready to tackle clients’ requests; moreover, `--threads=2` indicates that each worker process can spawn two threads. _Please note that the Gunicorn command shown below is for demonstrative purposes only._

```python
gunicorn --workers=4 --threads=2 -b 0.0.0.0:8080 app:app
[2024-04-16 23:35:59 +0300] [507149] [INFO] Starting gunicorn 21.2.0
[2024-04-16 23:35:59 +0300] [507149] [INFO] Listening at: http://0.0.0.0:8080 (507149)
[2024-04-16 23:35:59 +0300] [507149] [INFO] Using worker: gthread
[2024-04-16 23:35:59 +0300] [507150] [INFO] Booting worker with pid: 507150
[2024-04-16 23:35:59 +0300] [507151] [INFO] Booting worker with pid: 507151
[2024-04-16 23:35:59 +0300] [507152] [INFO] Booting worker with pid: 507152
[2024-04-16 23:35:59 +0300] [507153] [INFO] Booting worker with pid: 507153
```

It is worth noting the following:
- It is impossible to run more than one copy of this process as it binds itself to TCP port 8080. A TCP or UDP port can only be tied to one process.
- Process can be configured with any number of threads, and the HTTP requests arriving at port 8080 will be sent to the different threads.


## Race Conditions
Picture the following situation. You call a restaurant to reserve a table for a crucial business lunch. You are familiar with the restaurant and its setup. One particular table, number 17, is your preferred choice, considering it has a nice view and is relatively isolated. You call to make a reservation for Table 17; the host confirms it is free as no “Reserved” tag is placed on it. At the same time, another customer is talking with another host and making a reservation for the same table.
	![](Pasted%20image%2020250122050237.png)

Who really reserved the table? That’s a race condition.

Why did this happen? This unlucky situation happened because more than one host was taking reservations; furthermore, it took the host a few minutes to fetch the “Reserved” tag and put it on the table after updating the daily reservation book. There is at least a one-minute window for another client to reserve a reserved table.

Similarly, when one thread checks a value to perform an action, another thread might change that value before the action takes place.

### Example A
Let’s consider this scenario:
- A bank account has $100.
- Two threads try to withdraw money at the same time.
- Thread 1 checks the balance (sees $100) and withdraws $45.
- **Before Thread 1 updates the balance**, Thread 2 also checks the balance (incorrectly sees $100) and withdraws $35.

We cannot be 100% certain which thread will get to update the remaining balance first; however, let’s assume that it is Thread 1. Thread 1 will set the remaining balance to $55. Afterwards, Thread 2 might set the remaining balance to $65 if not appropriately handled. (Thread 2 calculated that $65 should remain in the account after the withdrawal because the balance was $100 when Thread 2 checked it.) In other words, the user made two withdrawals, but the account balance was deducted only for the second one because Thread 2 said so!

### Example B
Let’s consider another scenario:
- A bank account has $75.
- Two threads try to withdraw money at the same time.
- Thread 1 checks the balance (sees $75) and withdraws $50.
- **Before Thread 1 updates the balance**, Thread 2 checks the balance (incorrectly sees $75) and withdraws $50.

Thread 2 will proceed with the withdrawal, although such a transaction should have been declined.

Examples A and B demonstrate a Time-of-Check to Time-of-Use (TOCTOU) vulnerability.


### Example Code
Consider the following Python code with two threads simulating a task completion by 10% increments.
```python
import threading
import time

def increase_by_10():
    for i in range(1, 11):
        print(f"Thread {threading.current_thread().name}: {i}0% complete")

# Create two threads
thread1 = threading.Thread(target=increase_by_10, name="Thread-1")
thread2 = threading.Thread(target=increase_by_10, name="Thread-2")

# Start the threads
thread1.start()
thread2.start()

# Wait for both threads to finish
thread1.join()
thread2.join()

print("Both threads have finished completely.")
```

These two threads start together; they do nothing except print a value on the screen. Consequently, one would expect them to finish simultaneously, or at least the result to be consistent. However, in the program above, there is no guarantee which thread will finish first and how early it will be. Below is the first execution output:

```python
python t3_race_to_100.py
...
Thread Thread-1: 50% complete
Thread Thread-2: 90% complete
Thread Thread-2: 100% complete
Thread Thread-1: 60% complete
Thread Thread-1: 70% complete
Thread Thread-1: 80% complete
Thread Thread-1: 90% complete
Thread Thread-1: 100% complete
Both threads have finished completely.
```

Below is a second execution output:

```python
python t3_race_to_100.py 
...
Thread Thread-1: 90% complete
Thread Thread-1: 100% complete
Thread Thread-2: 10% complete
Thread Thread-2: 20% complete
Thread Thread-2: 30% complete
Thread Thread-2: 40% complete
Thread Thread-2: 50% complete
Thread Thread-2: 60% complete
Thread Thread-2: 70% complete
Thread Thread-2: 80% complete
Thread Thread-2: 90% complete
Thread Thread-2: 100% complete
Both threads have finished completely.
```

Running this program multiple times will lead to different results. In the first attempt, Thread-2 reached 100 first; however, in the second attempt, Thread-2 reached 100 second. We have no control over the output. If the security of our application relies on one thread finishing before the other, then we need to set mechanisms in place to ensure proper protection. Consider the following two examples to better understand the bugs’ gravity when we leave things to chance.

On the AttackBox, you can save the above Python code and run it multiple times to observe the outcome. For instance, if you saved it as `race.py`, you can run the script using the `python race.py` command.


## Causes
As we saw in the last program, two threads were changing the same variable. Whenever the thread was given CPU time, it rushed to change the value according to its instructions. Consequently, these two threads were “racing” to increase the value to 100. This program shows a straightforward example happening on a single host.

Generally speaking, a common cause of race conditions lies in shared resources. For example, when multiple threads concurrently access and modify the same shared data. Examples of shared data are a database record and an in-memory data structure. There are many subtle causes, but we will mention three common ones:

- **Parallel Execution**: Web servers may execute multiple requests in parallel to handle concurrent user interactions. If these requests access and modify shared resources or application states without proper synchronization, it can lead to race conditions and unexpected behaviour.
- **Database Operations**: Concurrent database operations, such as read-modify-write sequences, can introduce race conditions. For example, two users attempting to update the same record simultaneously may result in inconsistent data or conflicts. The solution lies in enforcing proper locking mechanisms and transaction isolation.
- **Third-Party Libraries and Services**: Nowadays, web applications often integrate with third-party libraries, APIs, and other services. If these external components are not designed to handle concurrent access properly, race conditions may occur when multiple requests or operations interact with them simultaneously.