---
layout: post
alias: "/blog/2016/09/01/cyber-security-challenge-2015-guess-the-algorithm/"
date: "2016-09-01T13:54:42+09:00"
tags: [ "ctf", "writeup", "crypto", "cyber-security-challenge" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/cyber-security-challenge-2015/cryptography/guess-the-algorithm" ]
---

# Cyber Security Challenge 2015: Guess the Algorithm

`md5 decryptor`とかで検索して適当なのに投げ付けたらでた。sha1だったがいい感じにしてくれた。


それでは芸がないのでとwriteupを見るとjohn the ripperを使えとあるが、動かない。Proを買えばよいのだろうか。

``` sh
$ echo 06f8aa28b9237866e3e289f18ade19e1736d809d > hash.txt
$ john hash.txt
No password hashes loaded (see FAQ)
$ john --format=raw-sha1 hash.txt
Unknown ciphertext format name requested
$ 
```

`lcrack`というのが`apt`で見つかったので試すも、$3,4$時間ぐらいかかりそうなのでだめ。

``` sh
$ lcrack -m sha1 -xb+ -s ' -~' hash.txt
-= [ Lepton's Crack ] =- Password Cracker [Jan  5 2010]
(C)  Bernardo Reino (aka Lepton) <lepton@runbox.com>
 and Miguel Dilaj (aka Nekromancer) <nekromancer@eudoramail.com>

xtn: initialized 'sha1' module
loaded: CSET[95] = {
   !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOP
  QRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
}
loaded: LSET[8] = { 1 2 3 4 5 6 7 8 }
dbg: loading 'hash.txt'
mode: null password, loaded 1 password
mode: incremental, loaded 1 password
Length = 1, Total = 95
Length = 2, Total = 9025
Length = 3, Total = 857375
Length = 4, Total = 81450625
Length = 5, Total = 7737809375
^CY: "A/n9, R = 7546471940
got Ctrl-C signal, exiting...
Lapse: 108.21s, Checked: 274915136, Found: 0/1, Speed: 2540570 passwd/s
lcrack -m sha1 -xb+ -s ' -~' hash.txt  108.20s user 0.01s system 99% cpu 1:48.21 total
```
