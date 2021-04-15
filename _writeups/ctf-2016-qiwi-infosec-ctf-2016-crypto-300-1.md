---
layout: post
redirect_from:
  - /writeup/ctf/2016/qiwi-infosec-ctf-2016-crypto-300-1/
  - /blog/2016/11/19/qiwi-infosec-ctf-2016-crypto-300-1/
date: "2016-11-19T01:31:03+09:00"
tags: [ "ctf", "writeup", "qiwi-ctf", "crypto", "diffie-hellman" ]
---

# Qiwi Infosec CTF 2016: Crypto 300_1

Diffie-Hellman鍵共有が題材のなにか。
$c$が未知でも$a, b, g^c$があれば$(g^c)^{ab} = g^{abc}$は求まるので`pow`するだけ。

``` python
#!/usr/bin/env python3
p = 8986158661930085086019708402870402191114171745913160469454315876556947370642799226714405016920875594030192024506376929926694545081888689821796050434591251
g = 6
a = 230
b = 250
gc = 5361617800833598741530924081762225477418277010142022622731688158297759621329407070985497917078988781448889947074350694220209769840915705739528359582454617

# The flag is the first 20 digits of the shared key in decimal form.
shared_key = pow(gc, a*b, p)
flag = str(shared_key)[:20]
print(flag)
```
