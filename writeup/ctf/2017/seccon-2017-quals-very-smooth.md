---
layout: post
alias: "/blog/2017/12/10/seccon-2017-quals-very-smooth/"
date: "2017-12-10T15:18:58+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "crypto", "network", "rsa" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

# SECCON 2017 Online CTF: Very smooth

## solution

[st98](https://twitter.com/st98_) uses [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) to retrieve the public key. I use [primefac](https://github.com/elliptic-shiho/primefac-fork) to factorize the key and Wireshark to read the flag.
The factored primes are below.

```
11807485231629132025602991324007150366908229752508016230400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
12684117323636134264468162714319298445454220244413621344524758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897
```
