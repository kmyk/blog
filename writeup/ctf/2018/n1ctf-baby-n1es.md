---
layout: post
redirect_from:
  - /writeup/ctf/2018/n1ctf-baby-n1es/
  - /blog/2018/03/12/n1ctf-baby-n1es/
date: "2018-03-12T13:29:55+09:00"
tags: [ "ctf", "writeup", "n1ctf", "crypto", "feistel-structure" ]
"target_url": [ "https://ctftime.org/event/584" ]
---

# N1CTF 2018: baby_N1ES

## solution

独自暗号ぽいのが与えられる。たぶん `N1ctf Encrypt System` で `N1ES`。
鍵は与えられているが`decrypt`関数がないので書くだけ。

ところで鍵が `wxy191 is so cute` なのでreconした。画像検索にたくさん引っかかる[パー](https://www.aliexpress.com/item/2017-New-Woman-Autumn-And-Winter-Sailor-Collar-Long-sleeve-Casual-Pullovers-Sweatshirts-Thick-Warm-Sweatshirts/32821989240.html)[カー](https://www.amazon.co.jp/dp/B0762QX6G1/)はたぶんはずれで正解は[この人](https://pwnhub.cn/personalinfo?id=41)。

## implementation

``` python
#!/usr/bin/env python2
from N1ES import N1ES
import base64
key = "wxy191iss00000000000cute"
n1es = N1ES(key)
cipher = base64.b64decode("HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx")
flag = n1es.decrypt(cipher)
print flag
```

``` python
$ diff N1ES.py N1ES.modified.py
8a9,18
> def round_sub(c, b):
>     f = lambda x, y: x + y - 2 * (x & y)
>     res = ''
>     for i in range(len(c)):
>         for a in map(chr, range(256)):
>             if chr(f(ord(a), ord(b[i]))) == c[i]:
>                 res += a
>                 break
>     return res
> 
75,79c85,97
< 
< 
< 
<         
<               
\ No newline at end of file
---

# N1CTF 2018: baby_N1ES
>     def decrypt(self, ciphertext):
>         if (len(ciphertext) % 16 != 0 or isinstance(ciphertext, bytes) == False):
>             raise Exception("ciphertext must be a multiple of 16 in length")
>         res = ''
>         for i in range(len(ciphertext) / 16):
>             block = ciphertext[i * 16:(i + 1) * 16]
>             L = block[:8]
>             R = block[8:]
>             L, R = R, L
>             for round_cnt in reversed(range(32)):
>                 L, R = (round_sub(R, self.Kn[round_cnt])), L
>             res += L + R
>         return res
```
