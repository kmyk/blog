---
layout: post
alias: "/blog/2016/09/09/easyctf-2015-scytcrypto/"
date: "2016-09-09T16:21:11+09:00"
tags: [ "ctf", "writeup", "easyctf", "crypto", "scytale-cipher" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/ekoparty-ctf-2015/crypto/cry50" ]
---

# EKOPARTY CTF 2015: SCYTCRYPTO

Scytale暗号は認識してなかった。
鍵長$3$。

``` python
>>> [ "ERTKSOOTCMCHYRAFYLIPL"[i::3] for i in range(3) ]
['EKOMYFI', 'RSTCRYP', 'TOCHALL']
```

ということで`EKO{MYFIRSTCRYPTOCHALL}`だそうな。
鍵のformat知らないと厳しい。
