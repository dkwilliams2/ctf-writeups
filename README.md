# 🚩 CTF Writeups

Step-by-step writeups of capture-the-flag (CTF) and TryHackMe challenges I've solved. Each one explains my methodology, the exact commands I ran, and the security lessons behind the challenge, not just the answer.

---

## 📂 Writeups

| Challenge | Category | Key techniques | Writeup |
|-----------|----------|----------------|---------|
| **Bart** | Linux privilege escalation | SUID binary abuse, filesystem enumeration, XOR secret sharing | [Read →](bart/README.md) |
| **Merkle Tree Tampering** | Cryptography | SHA-256, Merkle tree audit paths, brute-force recovery in Python | [Read →](merkle-tree/README.md) |
| **Beginner Network Security** | Network security (TryHackMe) | Port scanning, anonymous FTP, credential reuse, SSH | [Read →](network-security/README.md) |

---

## 🛠️ Skills demonstrated

- **Linux privilege escalation:** finding and abusing SUID/SGID binaries to pivot between user accounts
- **Enumeration:** scanning networks and filesystems, and working around broken tools when results don't add up
- **Cryptography:** hash functions, Merkle trees, XOR-based secret sharing
- **Network security:** service discovery, misconfigured FTP, credential reuse across services
- **Scripting:** writing Python one-liners and scripts to automate analysis and brute-force small keyspaces
- **Defensive thinking:** each writeup explains what was misconfigured and how to fix it

## 🧰 Tools used

`nmap` · `ftp` · `ssh` · `bash` · `python3` · `sha256sum` · `ls` / `awk` / `grep` · `hashlib`

---

## 📝 Writeup format

Every writeup follows the same structure:

1. **The challenge:** what the goal was
2. **Recon:** what I looked at first and why
3. **Exploitation / solution:** each step with the commands and output
4. **Answers:** the flag and any challenge questions
5. **Takeaways:** what the challenge teaches and how to defend against it

---

> ⚠️ All challenges were solved in legal, intentionally vulnerable training environments, and all flags are from competitions or rooms that have ended.
