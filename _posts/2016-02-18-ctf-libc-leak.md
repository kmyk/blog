---
category: blog
layout: post
title: "ctfにおけるlibc leakに関して"
date: 2016-02-18T16:24:40+09:00
tags: [ "ctf", "libc", "libc-leak" ]
---

libcは与えられているものだと思って解いていた過去問が、そうではなかったとらしく、その際るくすさんに教えてもらった話のまとめ。

## 手法

-   libcの中身を直接出力させる
    -   `.rodata`に格納されたversion情報を読む
        -   [CTF/Writeup/31C3 CTF/cfy - 電気通信大学MMA](https://wiki.mma.club.uec.ac.jp/CTF/Writeup/31C3%20CTF/cfy)
        -   [wibbly wobbly timey wimey (Pwnable:2pt), DEF CON CTF Qualifier 2015 writeup - しゃろの日記](http://charo-it.hatenablog.jp/entry/2015/05/19/114004)
    -   `.text`から`system`っぽいbyte列を探す
        -   [31C3 CTF - cfy Writeup, Home of the gn00bz](http://gnoobz.com/31c3-ctf-cfy-writeup.html)
    -   JIT-ROP
        -   [x64でDynamic ROPによるASLR+DEP+RELRO回避をやってみる - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/09/13/134924)
-   libcの関数のアドレスからlibcを推測
    -   <http://libcdb.com/>
    -   <https://github.com/niklasb/libc-database>
-   そもそもlibcを特定しない
    -   [ROP stager + Return-to-dl-resolveによるASLR+DEP回避 - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/07/15/023406)
-   他の問題と鯖を相乗りしている場合、別の問題で取ったshellでlibcを読む
    -   実行すればすぐ

## 他

### suggestions-for-running-a-ctf

(docs/suggestions-for-running-a-ctf-ja.md at master · scryptos/docs)[https://github.com/scryptos/docs/blob/master/suggestions-for-running-a-ctf-ja.md#リモート]

>   解く上でlibcリークが必要なとき、問題のバイナリと一緒にlibc.soも配布することを検討してください。libcを特定するスキルはCTFで試すようなものでもないです。

### --version

executable

``` sh
$ /usr/lib/libc.so.6 --version
GNU C Library (GNU libc) stable release version 2.22, by Roland McGrath et al.
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.3.0.
Available extensions:
        crypt add-on version 2.1 by Michael Glad and others
        GNU Libidn by Simon Josefsson
        Native POSIX Threads Library by Ulrich Drepper et al
        BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.archlinux.org/>.
```
