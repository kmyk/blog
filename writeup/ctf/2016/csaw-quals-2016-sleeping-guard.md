---
layout: post
redirect_from:
  - /writeup/ctf/2016/csaw-quals-2016-sleeping-guard/
  - /blog/2016/09/19/csaw-quals-2016-sleeping-guard/
date: "2016-09-19T22:09:45+09:00"
tags: [ "ctf", "writeup", "csaw-ctf", "crypto" ]
---

# CSAW Quals CTF 2016: Sleeping Guard

固定の文字列が飛んでくるserver。
直接ファイルで渡すのではだめだったのか。手元に落とすときbufferingを殺しておかないと末尾が切れるので注意。

``` sh
$ stdbuf -i0 -o0 nc crypto.chal.csaw.io 8000 > foo
```

ここで、`sleeping.png`という名の壊れたファイルがそれだけ与えられたのに等しいので、magic numberを直すとかxorされてるぐらいしか選択肢がない。
実際`WoAh_A_Key!?`でxorされていた。
`flag{l4zy_H4CK3rs_d0nt_g3T_MAg1C_FlaG5}`
