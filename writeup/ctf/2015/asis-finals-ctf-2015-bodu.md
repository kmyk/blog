---
layout: post
redirect_from:
  - /blog/2016/08/26/asis-finals-ctf-2015-bodu/
date: "2016-08-26T20:08:46+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "crypto", "rsa", "boneh-durfee-attack" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/asis-finals-ctf-2015/crypto/bodu" ]
---

# ASIS Cyber Security Contest 2015: bodu

解けない。writeupを見た: <https://kt.pe/blog/2015/10/asis-2015-finals-bodu/>。

与えられるのは`pub.key`。RSAの公開鍵。

``` sh
$ openssl rsa -text -noout -pubin -in pub.key
Public-Key: (1018 bit)
Modulus:
    03:a6:16:08:48:fb:17:34:cb:d0:fa:22:ce:f5:82:
    e8:49:22:3a:c0:45:10:d5:15:02:55:6b:64:76:d0:
    73:97:f0:3d:f1:55:28:9c:20:11:2e:87:c6:f3:53:
    61:d9:eb:62:2c:a4:a0:e5:2d:9c:d8:7b:f7:23:52:
    6c:82:6b:88:38:7d:06:ab:c4:27:9e:35:3f:12:ad:
    8e:c6:2e:a7:3c:47:32:1a:20:b8:96:44:88:9a:79:
    2a:73:15:2b:c7:01:4b:80:a6:93:d2:e5:8b:12:3f:
    a9:25:c3:56:b1:eb:a0:37:a4:dc:ac:8d:8d:e8:09:
    16:7a:6f:cc:30:c5:c7:85
Exponent:
    03:65:96:2e:8d:ab:a7:ba:92:fc:08:76:8a:5f:73:
    b3:85:4f:4c:79:96:9d:55:18:a0:78:a0:34:43:7c:
    46:69:bd:b7:05:be:4d:8b:8b:ab:f4:fd:a1:a6:e7:
    15:26:9e:87:b2:8e:ec:b0:d4:e0:27:26:a2:7f:b8:
    72:18:63:74:07:20:f5:83:68:8e:55:67:eb:10:72:
    9b:b0:d9:2b:32:2d:71:99:49:e4:0c:57:19:8d:76:
    4f:1c:63:3e:5e:27:7d:a3:d3:28:1e:ce:2c:e2:eb:
    4d:f9:45:be:5a:fc:3e:78:49:8e:d0:48:9b:24:59:
    05:96:64:fe:15:c8:8a:33
```

$10$進数にすると以下。$e$が$n$にそこそこ近い。(かといって、実は$\phi$ということはなかった。)

```
n = 2562256018798982275495595589518163432372017502243601864658538274705537914483947807120783733766118553254101235396521540936164219440561532997119915510314638089613615679231310858594698461124636943528101265406967445593951653796041336078776455339658353436309933716631455967769429086442266084993673779546522240901
e = 2385330119331689083455211591182934261439999376616463648565178544704114285540523381214630503109888606012730471130911882799269407391377516911847608047728411508873523338260985637241587680601172666919944195740711767256695758337633401530723721692604012809476068197687643054238649174648923555374972384090471828019
```

$e$が大きいことから$d$が小さいことが予想でき、そのような場合に対する手法(Low Private-Exponent Attack)がいくつかあるのでこれを使う。
特にBoneh-Durfee attackが今回使える。実装はSageMathによるものが利用できる。

<https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage>

``` python
#!/usr/bin/env python3
from Crypto.PublicKey import RSA
with open('pub.key') as fh:
    key = RSA.importKey(fh.read())
n = key.n
e = key.e
d = 89508186630638564513494386415865407147609702392949250864642625401059935751367507
key = RSA.construct((n, e, d))
with open('priv.key', 'w') as fh:
    fh.buffer.write(key.exportKey())
```

``` sh
$ openssl rsautl -decrypt -in flag.enc -inkey priv.key
ASIS{b472266d4dd916a23a7b0deb5bc5e63f}
```
