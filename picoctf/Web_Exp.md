# Challenges
1. SSTI1.
2. Cookies.
3. Web gauntlet.

## 1. SSTI1

## My solve

This challenge provided us a web interface with a text box which announces anything you input. First I checked the source code, which provided no hints.

<img width="796" height="304" alt="image" src="https://github.com/user-attachments/assets/602b93eb-65b2-4ca1-9ded-faf919e31ee3" />

Announcements are output in the /announcements page, manipulation of the url to find other pages resulted in errors.

The name of challenge is SSTI1, a quick google search about SSTI told me it stands for Server-side template injection which occurs when attackers can inject malicious code into a template that is executed server-side. 

A server-side injection requires the following process: 

<img width="441" height="416" alt="image" src="https://github.com/user-attachments/assets/8f66ba34-d6b1-4654-a554-171008898bc2" />

The first step, detect, is done by fuzzing the template using a sequence of special characters. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. 

So I tried the sequence of special characters - `` ${{<%[%'"}}%\`` 

<img width="1601" height="205" alt="image" src="https://github.com/user-attachments/assets/d833d165-7ade-4be9-b5d9-2c0d67b50e13" />

This raised an exception, confirming that the server is interpreting the input as template syntax. 

The next step was to identify the template engine, I inputted the payload ``{{7*'7'}}`` which give the output as `` 7777777 ``, confirming the template engine to be Jinja2. 

<img width="895" height="448" alt="image" src="https://github.com/user-attachments/assets/c0b9458f-755c-4207-96a1-6f07f2090497" />



Then I had to exploit the potential vulnerability. Jinja2 uses Python's Method Resolution Order (MRO) for method lookups within templates. MRO is the order in which Python searches classes and methods when resolving calls.


<img width="816" height="205" alt="image" src="https://github.com/user-attachments/assets/5e0aeaa6-9675-4f45-b690-c670200bda70" />


I used the command ``{{ ''.__class__.__mro__[1].__subclasses__() }}`` which provided me with a list of all classes loaded in memory. 

<img width="1835" height="992" alt="image" src="https://github.com/user-attachments/assets/29ee6d8a-3dbc-436f-8028-dc0acee56b09" />

Python's `popen` functions allow you to run operating system commands from within Python code. This is important in this challenge because I can't access the server's command line, but through SSTI I can access these functions to execute OS commands through the template.

I then looked for examples on how to use ``os.popen()`` commands.

<img width="1400" height="458" alt="image" src="https://github.com/user-attachments/assets/de2e20ba-a90d-42e7-a6aa-60c41cc0799f" />

I then announced ``{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`` which gave me the following output.

<img width="1593" height="192" alt="image" src="https://github.com/user-attachments/assets/a9c4504a-4309-46fc-84c0-4bbef23279d1" />

What this basically did was execute the id command. If I replace id with ls ``{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}`` it gives me the following output

<img width="1410" height="176" alt="image" src="https://github.com/user-attachments/assets/cbb1be98-e52e-47a8-b8df-e72544cedbb1" />


I then tried using ``{{request.application.__globals__.__builtins__.__import__('os').popen('cat flag').read()}}`` 

<img width="1306" height="190" alt="image" src="https://github.com/user-attachments/assets/87d4ba5d-0160-4dcb-a446-7bf586428a61" />

This finally gave me the flag.

**Flag:** 

```bash
picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_9451989d}
```

## References 
> 1) https://portswigger.net/web-security/server-side-template-injection
> 2) https://retherszu.github.io/vulnerabilities/web/server-side-template-injection/ssti-in-jinja2.html
> 3) https://onsecurity.io/article/server-side-template-injection-with-jinja2/

## 2. Cookies

## My Solve

This challenge took me to a web-interface where I could "search" for cookies. 

<img width="1142" height="695" alt="image" src="https://github.com/user-attachments/assets/260c7fa2-968a-4226-9213-79aaae159928" />

On entering the suggested prompt (snickerdoodle), I got the following response: 

<img width="977" height="453" alt="image" src="https://github.com/user-attachments/assets/9e01e8c0-9177-4823-b24a-2269c5d3f83b" />

Entering other prompts resulted in the message `` That doesn't appear to be a valid cookie. ``

I then opened developer tools to take a look at what cookies appeared to be shared

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/4a2029d5-0784-46ff-8e78-1e3572476f75" />

I noticed that there was only one cookie shared and its value was 0. I then headed over to Storage and modified the value of cookie to `1` - which gave me the following output. 

<img width="1900" height="747" alt="image" src="https://github.com/user-attachments/assets/c08bb4d6-f9bb-4849-b16a-05cb0d9667d8" />

On repeatedly changing the value of the cookie multiple times, the output kept changing, giving different types of *cookie* each attempt.

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/164dfb5a-0efb-4894-a26b-bc86151ffb96" />

I also noticed that the value was `-1` everytime the cookie wasn't found, modifying it to other negative values resulted in the same.

Finally after changing the value multiple times, the flag was found on value `18`

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/54303e79-b3e1-4c02-aeeb-9427677c7ff8" />

**Flag:**
```bash
picoCTF{3v3ry1_l0v3s_c00k135_064663be}
```
# 3. Web Gauntlet

> Can you beat the filters?
Log in as admin http://shape-facility.picoctf.net:55438/ http://shape-facility.picoctf.net:55438/filter.php

## Solution:

This challenge provides us with two links, and the first one takes us to a web interface with a login screen while the second one seems to be just a blank page with `` Round1: or``.

<img width="704" height="439" alt="image" src="https://github.com/user-attachments/assets/39928122-a367-42f5-8b58-b08a0b6d66c1" />

My first thought on seeing the login was to try basic SQL injection using ` admin' OR '1=1 ` but it led to no result, the page just refreshed itself. I then entered some random values to see where it would take me. 

<img width="1252" height="548" alt="image" src="https://github.com/user-attachments/assets/916899e1-488f-405b-aadc-5975e8912169" />

I noticed how the top left of the screen basically told us what command the login screen was working, it fetched details from the 'user' table to validate login credentials. 

I researched for more SQL payloads and after some tries I found that ` admin' -- ` worked and got me to round 2. 

The .php link displayed ` Round2: or and like = -- ` . I then remembered that the LAST .php page had also displayed ``or``, which was not working. So the filter.php was in fact telling me what keywords to **not** use. Which made sense because ` admin' -- ` no longer seemed to work.

After attempting a few prompts, `` admin'/* `` got me to the next level. This meant that the password was getting treated at as a command since it followed `/* `

This one had the filters: ``Round3: or and = like > < --`` 

This one required the prompt `` admin'; ``. I was basically terminating the command with this input and skipping the password. 

Round 4 had the filters ``Round4: or and = like > < -- admin``, so even admin was blocked now, but statement termination still wasn't. I had to find a way to input admin by getting past the filter. After a little bit of research, I found that || can be used to concat commands, using which I was able to type 

`admi'||'n';` which took me to the final round. This one blocked the union command ``Round5: or and = like > < -- union admin`` which I wasnt using anyways. Therefore `admi'||'n';` was accepted again and I was done with all the rounds.

After this on visiting the filter page I was able to find the flag.

<img width="1706" height="940" alt="image" src="https://github.com/user-attachments/assets/9495619a-34e1-4a8c-aefd-1bca2da4ce9f" />


## Flag:

```
picoCTF{y0u_m4d3_1t_79a0ddc6}
```

## Concepts learnt:

- I learned a little bit more about SQL like how /* can be used to add comments and || to concatenate.
- I also realized how websites can have mutliple vulnerabilties under the surface despite having filters to protect them.

## Notes:

- I was curious why `UNION` was blocked in round 4 and after digging around I found that an alternative solution was to use the union statement along with (/**/)  to bypass filters. The (/**/) basically works like spaces so we can use this to effectively write out entire SQL commands. `UNION` on the other hand combines queries together. 
- I also find it interesting that the prompt `` admi'||'n';`` is enough to bypass all the filters from round 1 to 5.

## Resources:

- https://www.geeksforgeeks.org/ethical-hacking/sql-injection-cheat-sheet/
- https://portswigger.net/web-security/sql-injection/cheat-sheet

***







