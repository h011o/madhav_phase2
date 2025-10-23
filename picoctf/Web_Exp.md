# Challenges
1. SSTI1
2. Web gauntlet
3. Cookies

## SSTI1

## My solve

This challenge provides us with a website where you can announce whatever you want. I checked the source code for the website, which provided no hints.

The name of challenge is SSTI1, a quick google search about SSTI told me it stands for Server-side template injection which occurs when attackers can inject malicious code into a template that is executed server-side. 

A server-side injection requires the following process: 

<img width="441" height="416" alt="image" src="https://github.com/user-attachments/assets/8f66ba34-d6b1-4654-a554-171008898bc2" />

The first step, Detect, is done by fuzzing the template using a sequence of special characters. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. 

So I tried the sequence of special characters - `` ${{<%[%'"}}%\`` 

<img width="1601" height="205" alt="image" src="https://github.com/user-attachments/assets/d833d165-7ade-4be9-b5d9-2c0d67b50e13" />

This raised an exception, confirming that the server is interpreting the input as template syntax. 

The next step was to identify the template engine, I inputted the payload ``{{7*'7'}}`` which give the output as `` 7777777 ``, confirming the template engine to be Jinja2. 

<img width="895" height="448" alt="image" src="https://github.com/user-attachments/assets/c0b9458f-755c-4207-96a1-6f07f2090497" />

The next step was to exploit the potential vulnerability. Jinja2 uses Python's Method Resolution Order (MRO) for method lookups within templates. MRO is the order in which Python searches classes and methods when resolving calls.
When a variable or method is referenced in {{ }}, Jinja2 will evaluate and return its value. 

I used the command {{ ''.__class__.__mro__[1].__subclasses__() }} which provided me with a list of all classes loaded in memory. 

<img width="1835" height="992" alt="image" src="https://github.com/user-attachments/assets/29ee6d8a-3dbc-436f-8028-dc0acee56b09" />



**Flag:** ``
```bash

```

## What I learned




## References 
https://portswigger.net/web-security/server-side-template-injection
(https://retherszu.github.io/vulnerabilities/web/server-side-template-injection/ssti-in-jinja2.html)

