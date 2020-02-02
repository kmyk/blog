---
layout: post
alias: "/blog/2016/11/21/rc3-ctf-2016-calculus/"
date: "2016-11-21T17:46:42+09:00"
title: "RC3 CTF 2016: Calculus"
tags: [ "ctf", "writeup", "rc3-ctf", "crypto", "guessing" ]
---

以下からflagを推測するエスパー問。
Crypto 200とは何だったのか。Crypto 300はさらに酷いっぽい(後からscryptosのslackを見に行ったらしほさんが解いてた)。

-   $\frac{d}{da}[\frac{1}{2}a^2] = a$
-   $\int[2n]dn = n^2+C$
-   $\frac{d}{dt}[\frac{1}{4}t^4+3] = t^3$
-   $\int[4i^3]di = i^4+C$
-   $\frac{d}{dd}[\frac{1}{3}d^6+6] = 2d^5$
-   $\int[6e^5]de = e^6+C$
-   $\frac{d}{dr}[\frac{1}{8}r^8 + \frac{1}{6}r^6 + \frac{1}{4}r^4 + \frac{1}{2}r^2 + r] = r^7+r^5+r^3+r+1$
-   $\int[8v^7 + 7v^6 + 4v^3+ 2v + 9]dv = v^8+v^7+v^4+v^2+9v+C$

flag: `RC3-2016-ANTIDERV` (小文字だと通らない)
