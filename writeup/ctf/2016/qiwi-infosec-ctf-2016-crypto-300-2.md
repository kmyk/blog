---
layout: post
alias: "/blog/2016/11/19/qiwi-infosec-ctf-2016-crypto-300-2/"
date: "2016-11-19T01:31:07+09:00"
title: "Qiwi Infosec CTF 2016: Crypto 300_2"
tags: [ "ctf", "writeup", "qiwi-ctf", "crypto", "diffie-hellman" ]
---

Diffie-Hellman鍵共有の秘密鍵を求める。
一般に離散対数問題は難しいが、$g^a, g^b$が小さいことから$a, b$が小さいことが推測でき、下から順に試せば解ける。

``` python
#!/usr/bin/env python3
p = 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047
g = 9444732965739290427392
ga = 842498333348457493583344221469363458551160763204392890034487820288
gb = 89202980794122492566142873090593446023921664

import itertools
for a in itertools.count():
    if pow(g, a, p) == ga:
        break
for b in itertools.count():
    if pow(g, b, p) == gb:
        break

shared_key = pow(g, a*b, p)
flag = str(shared_key)[: 20]
print(flag)
```
