<img width="1920" height="300" alt="image" src="https://github.com/user-attachments/assets/8ce3ff2d-8a28-462e-b1e4-76e0ecd85a1d" />


PHP2Shell

# Task 1 Introduction

## **Learning Objectives**

- Explain what `session.upload_progress` does and why it runs before any application code.
- Understand how a PHP memory bailout leaves a dangling pointer that survives into the next request.
- Distinguish the two CVEs: a memory-disclosure path and a remote-code-execution path.
- Run the public exploit chain to leak memory, defeat ASLR and execute a command.
- Detect the attack and apply the mitigations that actually work.

## **Connecting to the Lab**

Start the target by pressing the **Start Machine** button at the top of this task. Give it about two minutes to boot. The machine runs a vulnerable copy of PHP (8.4.26) behind Apache, served from a container that listens on `127.0.0.1:8088`, so you attack it from a shell on the machine itself rather than across the network.

Connect over SSH using the credentials below, from the AttackBox or your own terminal:

## **Credentials**

```
Username: ubuntu
Password: tryhackme
Connection via: SSH 
ssh ubuntu@MACHINE_IP
```

Everything you need is already on the machine: the vulnerable server is running, and the exploit is in the `ubuntu` user's home directory. Work through the tasks in order, as each one builds on the last.

After logging in to the SSH I found the docker container running for this room and examined it.

```bash
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ docker ps
CONTAINER ID   IMAGE               COMMAND                  CREATED      STATUS          PORTS                    NAMES
d77a04da7d60   php:8.4.26-apache   "docker-php-entrypoi…"   2 days ago   Up 23 minutes   127.0.0.1:8088->80/tcp   php2shell-target
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ docker exec php2shell-target whoami
root
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$
```

The container itself is running with `root` priviliges but after reaching at the Task-6 the exploitation part , we ran commands using exploit.py with `www-data` priviliges.Not sure what made them differ I researched for a while and found this interesting security feature.

<aside>
💡

- **Why this says `root`:** Running `docker exec` interacts directly with the Docker daemon from the host machine, forcing the container to spawn a new process as the container's default user (`root`).
- **Why the exploit gets `www-data`:** The exploit targets `index.php` over HTTP. The incoming web request is handled by an Apache worker process, which drops privileges down to `www-data` for safety. The injected payload inherits these lower web-server permissions, **not** the root daemon permissions
</aside>

Pretty basic concept but I wasn’t aware of this😅,glad I looked into it.

# Task 2 A Harmless Feature: Upload Progress

Every vulnerability abuses something that was built to be useful, and this one is no exception. Before looking at the bug, it is worth understanding the feature it stands on, because the feature is where the attacker's reach comes from.

When a browser uploads a large file, the server has no simple way to tell the page how far the upload has got. PHP solves this with a feature called `session.upload_progress`. While PHP is still reading a `multipart/form-data` request body off the wire, it writes a running description of the upload, its name, its size and how many bytes have arrived so far, into the user's `$_SESSION`. A second request can then read that session data and report progress back to the browser. The feature is enabled by default, and it is switched on for a given upload by including a form field whose name matches the `session.upload_progress.name` setting, which defaults to `PHP_SESSION_UPLOAD_PROGRESS`.
<img width="1086" height="310" alt="image" src="https://github.com/user-attachments/assets/ade79270-36c2-4cf9-a8c2-81f0fb2db000" />


A multipart POST carrying the PHP_SESSION_UPLOAD_PROGRESS field causes PHP to write progress data into the session during body parsing, before request initialisation and before the target script runs.

The detail that matters is *when* this happens. Parsing the request body is one of the first things PHP does, long before it initialises the request environment and long before it compiles and runs the script the URL points at. The progress updates are written from inside the body-parsing callbacks, so they occur **before any application code executes**. That has a consequence the feature's designers never intended to expose: reaching this code needs no `session_start()` in the target page, no valid login, and in fact no application logic at all. Any URL on the server that accepts a POST request is enough, even one whose script does nothing but print a single line.

This pre-execution window is the foothold. The whole of PHP2Shell happens inside it, driven entirely by what the attacker puts in an ordinary multipart upload, while the application that owns the server is still fast asleep.

- What is the default name of the form field that switches on PHP's upload-progress tracking?
    
    `XXXXXXXXXXXX`
    

# Task 3 The Bug: A Bailout at the Wrong Moment

The upload-progress feature is not itself the vulnerability. The vulnerability is what happens when PHP runs out of memory while that feature is in the middle of its work, and to see it you need to know how PHP handles a fatal error.

PHP caps how much memory a single request may use with the `memory_limit` setting. When a request tries to exceed it, PHP cannot simply carry on, so it performs what the engine calls a **bailout**: it uses a `longjmp()` to jump straight back to a safe recovery point, abandoning whatever it was doing. This is the mechanism behind the familiar "Allowed memory size exhausted" fatal error. Normally a request tidies up after itself, freeing memory and clearing the pointers that referred to it, but a bailout skips all of that. It is an emergency exit, not an orderly shutdown.

The flaw is a matter of timing. If the out-of-memory condition strikes *after* the engine has freed a block of memory but *before* it has cleared the pointer that still refers to that block, the bailout leaves the pointer behind, pointing at memory that is no longer valid. This is a classic dangling pointer, classified as **CWE-824: Access of Uninitialised Pointer**.
<img width="1020" height="419" alt="image" src="https://github.com/user-attachments/assets/99028359-9b46-4512-9f19-8e75d511f2f9" />


An out-of-memory bailout fires between freeing a block and clearing its pointer, so a dangling pointer survives the dead request and is reused by the next request on the same Apache worker.

On its own, a dangling pointer in a request that has just died would be harmless, because the request is over. What makes it dangerous is the server model. Under Apache's **prefork** configuration with `mod_php`, a single worker process serves one request after another without restarting between them. The stale pointer therefore does not vanish with the failed request; it stays in the worker's memory, and the *next* request to land on that same worker finds the engine reaching through a pointer it never reset. An attacker who controls what gets allocated into that freed space in the second request controls what the pointer now points at.

From this single defect the researchers built two distinct attacks, which is why PHP2Shell carries two CVE numbers. **CVE-2026-109618** is a *memory-disclosure* flaw: the stale pointer is read back as a string with an attacker-influenced, oversized length, and PHP returns the result in a response header, handing the attacker a window into the worker's memory. **CVE-2026-109619** is the *remote-code-execution* flaw, which turns the corrupted state into control over the program's flow. The PHP changelog addresses both with a single description, "Avoid state corruption via bailout", which names the root cause precisely. The next three tasks follow that chain in order: confirm the target, use the disclosure to defeat ASLR, and then turn the corruption into a shell.

- What one-word name does the PHP engine give to the longjmp it performs to abort a request that hits a fatal error such as running out of memory?
    
    `xxxxxxx`
    
- What is the CWE identifier for the weakness class behind PHP2Shell? (format: CWE-NNN)
    
    `CWE-XXX`
    

# Task 4 Reconnaissance: Confirming the Target

With the machine started and an SSH session open as the `ubuntu` user, the first job is to confirm what you are dealing with. Everything in this room runs from the machine itself against the vulnerable server on `127.0.0.1:8088`.

The vulnerable server runs as a container. List it and read the PHP version it ships:

```bash
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ docker ps --format '{{.Names}} {{.Image}} {{.Status}}'
php2shell-target php:8.4.26-apache Up 22 minutes
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ docker exec php2shell-target php -v
PHP 8.4.26 (cli) (built: Oct 21 2026 00:31:19) (NTS)
Copyright (c) The PHP Group
Built by https://github.com/docker-library/php
Zend Engine v4.4.26, Copyright (c) Zend Technologies
    with Zend OPcache v8.4.26, Copyright (c), by Zend Technologies
```

The server is **PHP 8.4.26, one release short of the 8.4.27 fix, so it is vulnerable**. Now look at the page you will be attacking:

```bash
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ curl -s http://127.0.0.1:8088/index.php
OK
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ docker exec php2shell-target cat /var/www/html/index.php
<?php echo "OK\n"; ?>
```

The entire application is one line that prints `OK`. There is no login form, no file upload, no database, and certainly no bug in this code to exploit. That is the point worth pausing on: if the attack works against this page, it works against the runtime, not the application, and a real target such as a WordPress or Laravel site is no better protected simply because its own code is sound.

The server runs the ordinary prefork `mod_php` setup with `session.upload_progress` enabled as it is by default. For the lab it is cut down to a single worker, and `memory_limit` is set low, so the dangling pointer is reliably reused and the out-of-memory condition is easy to provoke; a production host would run many workers with a higher limit, which makes the timing harder to hit but not impossible. The exploit you will use is already on the machine:

```bash
ubuntu@tryhackme:~$ ls ~/php2shell-bypass-aslr-exp
docker  exploit.py  out  README.md  readme_en.md  src  tools
```

With the target identified and confirmed vulnerable, you can move on to the first half of the attack: making the server hand you its own memory.

- What version of PHP is the target server running?
    
    `8.X.XX`
    
- What single word does the target page at /index.php print in response?
    
    `XX`
    

# Task 5 Leaking Memory and Defeating ASLR (CVE-2026-109618)

Modern systems load code and data at randomised addresses, a defence called Address Space Layout Randomisation (ASLR). An attacker who wants to redirect execution has to know where things actually are in memory, and ASLR is meant to deny that knowledge. CVE-2026-109618 removes it, by turning the dangling pointer into a leak of the worker's own memory.

The mechanism reuses the bailout from the previous task. An out-of-memory condition is provoked while a session identifier is being handled, which leaves a stale pointer to the session id. A following request reoccupies that freed space so the stale pointer now describes a string whose length the attacker has inflated far beyond the real data. When PHP sends the session cookie, it reads that oversized session-id string and returns it to the client in the **Set-Cookie: PHPSESSID** response header. The header now carries whatever happened to sit in the worker's memory after the string, which the research measured at up to roughly 67 KB of process memory per request. In a real deployment that memory can hold other users' passwords, session cookies, API keys, and even TLS private keys; for the exploit, it holds the addresses it needs.

A stale PHPSESSID pointer is read with an oversized length, so PHP copies adjacent worker memory into the Set-Cookie response header, disclosing heap and library addresses to the attacker.
<img width="1133" height="399" alt="image" src="https://github.com/user-attachments/assets/9a629fc7-ad4d-4df0-9560-3a1b22d88ae6" />


The exploit runs this leak twice. The first pass discloses the base address of PHP's memory heap, and the second discloses the base address of the PHP library (`libphp`) by reading a pointer whose offset into the library is known. Between them, the two leaks tell the attacker exactly where the heap and the engine's own code live in this specific worker, which is all that was missing to defeat ASLR. You can watch both leaks happen by running the exploit; they are the first thing it does, and the same run then goes on to the code-execution step you will complete in the next task.

```bash
ubuntu@tryhackme-2404:~/php2shell-bypass-aslr-exp$ python3 exploit.py -u http://127.0.0.1:8088/index.php
[*] target http://127.0.0.1:8088/index.php (cmd='id>/out/p1')
[*] offsets loaded from /home/ubuntu/php2shell-bypass-aslr-exp/out/offsets.env
[*] offsets: zif=0x465370 dtor=0x65eb60 htdata=0x690d8
[*] rotating worker over HTTP
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x745fb3400000
[*] rotating worker over HTTP
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x745fb5066000
[*] rotating worker over HTTP
[*] stage 3: HTDATA=0x745fb34690d8 ZIF=0x745fb54cb370
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The two `[+]` lines are the disclosure: the heap chunk base and the `libphp` base, each read straight out of a `Set-Cookie` header. The addresses differ on every run, which is ASLR doing its job; the attack simply reads them out each time rather than guessing them. With the heap and the library located, the second CVE can take over and turn the corruption into execution.

- Which HTTP response header does CVE-2026-109618 abuse to return leaked process memory to the attacker?
    
    `XXX-XXXXXXX`
    

# Task 6 From a Leak to a Shell (CVE-2026-109619)

The leak told the attacker where everything is. CVE-2026-109619 is what turns that knowledge into a command running on the server. It works by reoccupying the freed memory not with data to read, but with a carefully forged object that hijacks the engine's own clean-up machinery.

When PHP destroys a value, it may call a function pointer stored alongside it, a destructor, to release the value's resources. The exploit reoccupies the dangling reference with a forged internal structure (a `HashTable`) whose destructor pointer, `pDestructor`, has been set to the address of `system()` inside the PHP library, an address the leak in the previous task made known. When the engine tidies up that value at the end of request handling, it believes it is calling a harmless destructor and instead calls `system()` with attacker-controlled bytes as its argument. The command runs as the web server user. Nothing in the attack needs the C library or any gadget outside PHP itself; the whole finish is built from the engine's own code.
<img width="1041" height="433" alt="image" src="https://github.com/user-attachments/assets/804d0324-0e2e-46e3-88b2-ba8d6ad50665" />


The full chain: rotate the worker, leak the heap base, leak the libphp base to defeat ASLR, then forge a HashTable whose destructor points at system() so cleanup executes the attacker's command as the web user.

Running the exploit with no command argument performs the whole chain and proves execution by running `id` on the target:

```bash
ubuntu@tryhackme:~/php2shell-bypass-aslr-exp$ python3 exploit.py -u http://127.0.0.1:8088/index.php
[*] target http://127.0.0.1:8088/index.php (cmd='id>/out/p1')
[*] offsets loaded from out/offsets.env
[*] rotating worker over HTTP
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x70d1a2c00000
[*] rotating worker over HTTP
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x70d1a4911000
[*] rotating worker over HTTP
[*] stage 3: HTDATA=0x70d1a2c690d8 ZIF=0x70d1a4d76370
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

That is remote code execution, from nothing but multipart POST requests to a page that prints `OK`, against a server with no application vulnerability of any kind. The whole chain completes in under ten seconds.

To retrieve the flag, run a command of your own. The payload that carries it is tiny, with only fourteen bytes for the command and its redirection, so the flag is exposed at the short path `/f` on the target. The command below reads it into the shared `out` directory, which the tool then prints back:

```bash
ubuntu@tryhackme:~/php2shell-bypass-aslr-exp$ python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'cat /f>/out/p1' --proof-file out/p1
[*] target http://127.0.0.1:8088/index.php (cmd='cat /f>/out/p1')
[*] offsets loaded from out/offsets.env
[*] rotating worker over HTTP
[*] stage 1: heap leak (attempt 1/3)
[+] chunk base = 0x70d1a2c00000
[*] rotating worker over HTTP
[*] stage 2: libphp leak (attempt 1/3)
[+] libphp base = 0x70d1a4911000
[*] rotating worker over HTTP
[*] stage 3: HTDATA=0x70d1a2c690d8 ZIF=0x70d1a4d76370
[+] W3 attempt 1
PROOF: THM{...}
```

Submit the flag below. If a run ever stops short at the leak stage, simply run it again; the corruption is probabilistic, and the exploit retries the fragile stages for you.

- When the exploit runs, which system user do the commands execute as?
    
    `yyy-xxxx`
    
- What is the flag returned by the exploit?
    
    `THM{XXXXXXXX}`
    

# Task 7 Detection, Mitigation and the Real Fix

Because PHP2Shell lives in the runtime, the instinct to "update the website" misses it entirely. Updating WordPress, Drupal, Joomla or Laravel changes the application; the vulnerable code is in PHP, underneath all of them. The only complete fix is to patch the PHP runtime itself, by updating the PHP package your distribution ships or the base image your container is built from, to 8.5.12, 8.4.27, 8.3.36 or 8.2.35, and then restarting every worker so no process keeps running the old code.

Until that patch can be applied, several interim measures reduce exposure, though the PHP team is clear that none is a complete substitute for patching. Disabling the feature the attack relies on, by setting `session.upload_progress.enabled = 0` and restarting all workers, removes the trigger for most of the reported techniques. Turning off the opcode cache with `opcache.enable = 0` frustrates the code-execution path. On PHP 8.5, `fatal_error_backtraces = 0` addresses CVE-2026-109619 specifically. At the network edge, rejecting `multipart/form-data` requests blocks the delivery mechanism, at the cost of breaking legitimate file uploads. Running the PHP process with least privilege limits what an attacker gains if the chain does land.

One defence that does *not* help is worth calling out. A web application firewall that runs as a PHP module inspects traffic only once PHP hands control to the application, but this attack does its damage before the application ever runs. The malicious work is complete while the request is still being parsed, so an in-process filter never gets the chance to see it. Protection has to sit either in the patched runtime or at a layer in front of PHP.

For detection, the attack leaves distinctive marks. The disclosure path produces **abnormally large PHPSESSID values** in `Set-Cookie` response headers, which stand out sharply against the fixed-length identifiers PHP normally issues. The delivery requests are **large multipart POST bodies with very high field counts** that carry the `PHP_SESSION_UPLOAD_PROGRESS` field, and the memory exhaustion that drives the bug shows up as **PHP worker crashes and out-of-memory errors** in the logs. Any of these, and especially the combination, is worth alerting on while patching is in progress.

- Which PHP 8.4 release fixes PHP2Shell?
    
    `8.4.X`
    
- Which php.ini directive, set to 0, disables the feature the attack relies on for delivery?
    
    `S______._______________.E_____ = 0`
    

# Task 8 Conclusion

PHP2Shell is a reminder that the software stack does not stop at the application. A single mistake in how the PHP engine recovered from running out of memory, present and unnoticed since 2012, exposed an unauthenticated path to code execution on a large share of the web's servers at once, independent of which framework or CMS sat on top. The lesson for defenders is to treat the runtime as part of the attack surface and to patch it with the same urgency as the application, because a flaw this deep cannot be reached by securing the layers above it.

In this room you saw the harmless upload-progress feature that gave the attack its pre-authentication foothold, the memory bailout that left a pointer dangling into the next request, the memory disclosure that read the server's own addresses out of a cookie header to defeat ASLR, and the forged destructor that finished the job as remote code execution. You then ran the full chain against a vulnerable server and read a flag as the web server user, from nothing but ordinary HTTP requests.

If you would like to go deeper, read the engine internals in PHP's own advisories, GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp, and compare this class of bug with the memory-safety issues you may have met in compiled languages. The underlying weakness, a pointer used after the thing it pointed to was gone, is the same story told in a new setting.

Well done for completing the room.
