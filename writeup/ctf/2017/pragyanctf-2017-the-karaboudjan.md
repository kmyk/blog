---
layout: post
alias: "/blog/2017/03/06/pragyanctf-2017-the-karaboudjan/"
date: "2017-03-06T00:03:19+09:00"
title: "Pragyan CTF 2017: The Karaboudjan"
tags: [ "ctf", "pragyan-ctf" ]
---

問題文は次。brainfuckぽい記号列とclue.zipが与えられる。

>   Captain Haddock is on one of his ship sailing journeys when he gets stranded off the coast of North Korea. He finds shelter off a used nuke and decides to use the seashells to engrave a message on a piece of paper. Decrypt the message and save Captain Haddock.

``` brainfuck
->-.>-.---.-->-.>.>+.-->--..++++.
.+++.
.->-.->-.++++++++++.+>+++.++.-[->+++<]>+.+++++.++++++++++..++++[->+++<]>.--.->--.>.
```

しかし単に辞書攻撃するだけ。

``` sh
$ fcrackzip --dictionary --init-password /usr/share/dict/american-english --use-unzip clue.zip


PASSWORD FOUND!!!!: pw == dissect

$ unzip clue.zip
Archive:  clue.zip
[clue.zip] clue.pcap password: 
  inflating: clue.pcap 

$ xxd clue.pcap
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
00000010: ffff 0000 0100 0000 aa77 9f47 90a2 0400  .........w.G....
00000020: 4d00 0000 4d00 0000 0000 0000 0000 0000  M...M...........
00000030: 0000 0000 0800 4500 003f 0000 4000 4011  ......E..?..@.@.
00000040: 3cac 7f00 0001 7f00 0001 8001 07e1 002b  <..............+
00000050: 0000 0101 0008 244a 4143 4b50 4f54 2474  ......$JACKPOT$t
00000060: 6865 666c 6167 6973 2d7b 356e 3030 705f  heflagis-{5n00p_
00000070: 6430 3939 7d                             d099}
```

flag: `pragyanctf{5n00p_d099}`
