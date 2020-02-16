---
layout: post
alias: "/blog/2017/08/07/sha2017-ctf-stack-overflow/"
date: "2017-08-07T16:50:15+09:00"
tags: [ "ctf", "writeup", "sha-ctf", "crypto", "aes", "xor" ]
---

# SHA2017 CTF: crypto 100 - Stack Overflow

## solution

AES + counter modeだが、counterの値が固定なので実質xorされてるだけ。
PDFのmagic numberあたりをきっかけ復元する。

## implementation

``` python
#!/usr/bin/env python3
import sys
import operator

magic = b'%PDF-1.3 \x0a1 0 ob'
with open('flag.pdf.enc') as fh:
    enc = fh.buffer.read()
key = bytes(list(map(operator.xor, magic, enc)))
raw = bytes(list(map(operator.xor, enc, key * len(enc))))
sys.stdout.buffer.write(raw)
```
