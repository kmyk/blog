---
layout: post
alias: "/blog/2017/12/10/seccon-2017-quals-sha-1-is-dead/"
title: "SECCON 2017 Online CTF: SHA-1 is dead"
date: "2017-12-10T15:16:40+09:00"
tags: [ "ctf", "writeup", "seccon", "seccon-quals", "crypto", "sha1", "hash-collision", "shattered" ]
"target_url": [ "https://ctftime.org/event/512/" ]
---

## problem

submit files such that:

-   SHA1(file1) $=$ SHA1(file2)
-   SHA256(file1) $\ne$ SHA256(file2)
-   $2017$KiB $\lt$ file1, file2 $\lt$ $2018$KiB

You should take care the difference between `KB` and `KiB`. I've mistaken this and been confused.

## solution

Hash functions having the Merkle-Damgard structure have the following property: $H(a) = H(b) \land \mathrm{length}(a) = \mathrm{length}(b)$ implies $\forall c. H(a \oplus c) = H(b \oplus c).
So you can get a desired pair with simply padding the pair, [shattered](https://shattered.io/).

``` sh
$ { cat shattered-1.pdf ; yes | head -c 1643485 } > file-1.pdf
$ { cat shattered-2.pdf ; yes | head -c 1643485 } > file-2.pdf
```
