---
layout: post
alias: "/blog/2017/03/06/pragyanctf-2017-shane-and-the-binary-files/"
date: "2017-03-06T00:02:36+09:00"
title: "Pragyan CTF 2017: Shane and the binary files"
tags: [ "ctf", "pragyan-ctf", "java", "jad" ]
---

普通の問題。pragyanctfにはguessingを期待しているのでそういのはやめてほしい。

[JAD](https://varaneckas.com/jad/)でdecompileすると、汚ないが特に難読化ということもないコードが出てくる。切り出して横で実行するなど適当に。

``` sh
$ java nq2eige2ig2323f
Enter in a key to unlock :

76bd43a074fc575adc01aa748be6349cC
Congratulations ! You're right ! The flag is aKMqGxs4duK7PxM33Bln
```

flag: `pragyanctf{aKMqGxs4duK7PxM33Bln}`
