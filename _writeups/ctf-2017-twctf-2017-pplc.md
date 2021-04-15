---
layout: post
redirect_from:
  - /writeup/ctf/2017/twctf-2017-pplc/
  - /blog/2017/09/04/twctf-2017-pplc/
date: "2017-09-04T13:34:05+09:00"
tags: [ "ctf", "writeup", "twctf", "ppc" ]
---

# Tokyo Westerns CTF 3rd 2017: pplc

## private

縛りgolf。`dir(p)[0]`は`_Private__flag`

```
$ nc ppc1.chal.ctf.westerns.tokyo 10000
eval('p.%s()'%dir(p)[0])

TWCTF{__private is not private}
```

## local

code objectを覗けばよい

```
$ nc ppc1.chal.ctf.westerns.tokyo 10001
get_flag.__code__.co_consts

(None, 'TWCTF{func_code is useful for metaprogramming}')
```

## comment

commentといいつつ実際はdocstringなので通常の方法で取れる

```
$ nc ppc1.chal.ctf.westerns.tokyo 10002
comment_flag.__doc__

Welcome to unreadable area!
FLAG is TWCTF{very simple docstring}
```
