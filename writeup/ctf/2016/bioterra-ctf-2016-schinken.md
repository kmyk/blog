---
layout: post
alias: "/blog/2016/08/22/bioterra-ctf-2016-schinken/"
date: "2016-08-22T11:47:57+09:00"
tags: [ "ctf", "writeup", "bioterra-ctf", "xor", "crypto" ]
---

# BioTerra CTF 2016: Schinken

The service encrypts a string with a password, into a pdf file (or the tex).
You can notice that the letters of Lerem-ipsum have different fonts.

Actually, this fonts contain bits about the xor-value of the plaintext and the password.
You can find this by trying pairs like: password is `AAAA` and text is `AAAA`, or password is `AAA` and text is `ABCD`.
Especially, the only letters `ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_` are allowed, and the integers to xor is the indices in the letters (not ascii-code).

To decrypt it, `pdf2ps` helped me.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest='command')
subparser = subparsers.add_parser('query')
subparser.add_argument('--name',     required=True)
subparser.add_argument('--address',  required=True)
subparser.add_argument('--text',     required=True)
subparser.add_argument('--password', required=True)
subparser.add_argument('--do',       required=True, choices=[ 'letter', 'source' ])
subparser = subparsers.add_parser('crack')
subparser.add_argument('file')
subparser.add_argument('--key', default='Geheim')
parser.add_argument('--host', default='pwn.bioterra.xyz')
parser.add_argument('--port', default=6969, type=int)
args = parser.parse_args()
context.log_level = 'debug'

def query(name, address, text, password, do):
    import base64
    p = remote(args.host, args.port)
    p.recvuntil('Enter your name:')
    p.sendline(name)
    p.recvuntil('Enter your address:')
    p.sendline(address)
    p.recvuntil('Enter your text to encrypt:')
    p.sendline(text)
    p.recvuntil('Enter a password:')
    p.sendline(password)
    p.recvuntil('Choice:')
    p.sendline(do[0])
    p.recvuntil('-----BEGIN MESSAGE----')
    s = p.recvuntil('-----END MESSAGE-----')
    s = base64.b64decode(s)
    p.recvall()
    p.close()
    return s

def crack(pdfstr):
    import re
    import subprocess
    p = subprocess.Popen(['pdf2ps', '-', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    psstr, _ = p.communicate(pdfstr)

    msg = ''
    bit = []
    state = None
    for line in psstr.split('\n'):
        if re.search(r'/R6 \S+ Tf', line):
            state = 0
        if re.search(r'/R12 \S+ Tf', line):
            state = 1
        for s in re.findall(r'\(([^)]+)\)', line):
            for c in s.strip('()'):
                msg += c
                bit += [state]
    i = msg.index('Lorem')
    j = msg.index('Mitfreundlichen')
    msg = msg[i : j]
    bit = bit[i : j]
    log.info('msg: %s', repr(msg))
    log.info('bit: %s', repr(bit))
    log.info('len: %d', len(bit))
    assert len(bit) % 5 == 0

    return bit

if args.command == 'query':
    s = query(args.name, args.address, args.text, args.password, args.do)

    if args.do == 'letter':
        import tempfile
        import subprocess
        import time
        with tempfile.NamedTemporaryFile(suffix='.pdf') as fh:
            fh.write(s)
            fh.flush()
            subprocess.call(['xdg-open', fh.name])
            time.sleep(2)

    elif args.do == 'source':
        import itertools
        import re
        log.info(s)
        for line in s.split('\n'):
            if len(re.findall(r'\\fontfamily', line)) > 3:
                for i in itertools.count():
                    m = re.search(r'^\\fontfamily{(\w\w\w)}\\selectfont (\S) ?', line)
                    if not m:
                        break
                    log.info('%d %s: %d', i, m.group(2), { 'ppl': 0, 'phv': 1 }[m.group(1)])
                    if i % 5 == 4:
                        log.info('')
                    line = line[m.end(): ]

elif args.command == 'crack':
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_'
    with open(args.file) as fh:
        s = crack(fh.read())
    flag = ''
    for i in range(len(s) // 5):
        a = int(''.join(map(str, s[i*5 : i*5+5])), 2)
        b = alphabet.index(args.key[i % len(args.key)].upper())
        c = alphabet[a ^ b]
        flag += c
    log.info(flag)
```
