---
layout: post
alias: "/blog/2016/08/21/hackcon-2016/"
date: "2016-08-21T01:29:48+09:00"
tags: [ "ctf", "writeup", "hackcon", "rsa", "rsa-oaep", "oaep", "brainfuck", "crypto" ]
---

# HackCon 2016

## StartedFromTheBottom

Reversing. Read the binary and summarize it, like below:

``` c
bool is_valid(char *s) {
    int l = strlen(s);
    uint32_t sum = 0xdeadbeef;
    for (int i = 0; i < l; ++ i) {
        sum = sum * 8 + arg[i];
    }
    return sum == 0xcafebabe;
}
main() {
    fgets(buf, 0x20, stdin);
    if (is_valid(buf)) {
        puts(getenv("flag"));
    }
}
```

It seems there are many keys. The probability thet a string is a key is $\frac{1}{256^4}$, and you can adjust the lowest byte, it becomes $\frac{1}{256^3}$. This is not small.
You can find a key in bruteforce.

``` c++
#include <iostream>
#include <random>
#include <cctype>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int check(string const & s) {
    uint32_t acc = 0xdeadbeaf;
    for (char c : s) acc = 8 * acc + c;
    uint32_t diff = 0xcafebabe - acc * 8;
    return diff < 0x100 and isprint(diff) ? diff : -1;
}
int main() {
    random_device dev;
    default_random_engine gen(dev());
    uniform_int_distribution<char> dist(' ', '~');
    string s(8, 'A');
    char c;
    while ((c = check(s)) == -1) {
        repeat (i, s.length()) s[i] = dist(gen);
    }
    cout << s << c << endl;
    return 0;
}
```

## Help a n00b pliz

<small>
I didn't know the OAEP, and [@elliptic_shiho](https://twitter.com/elliptic_shiho) solved this in the contest.
</small>

RSA cipher is used, especially RSA-OAEP.
[Optimal Asymmetric Encryption Padding](https://en.wikipedia.org/wiki/Optimal_Asymmetric_Encryption_Padding) is the way to enforce a cipher.
In short, the OAEP is a method something like: hashing plaintexts as a preprocessing must makes more secure.

The magic number is a $\phi = (p-1)(q-1)$.
You can factrize $n$ with $\phi$ or the <http://factordb.com>.

``` python
#!/usr/bin/env python3

# Hi d0rkf0rce, I was trying to setup an RSA key myself ... N was set as
n = 27554341234325806742716465451216524672595447919304850637064219542729814328202676387561154175188204624894575424004190815736798277306646200007362824444984235900887686209887989471971837946286068039230967669298101493802987250668663968489404427616923945008553706682588440402642022107160279111970813001769125144160981955619256311678497842429348810714179895140353432460873680236125023285896278220224124173530157559877857583541236440550085510341350034262384944452679681733672970090393853456354728769750083127095029970793577304343958201598759646018974544024756484677430899865099392181088697032441561919756953472132635695403211
# and that magic number which can break it came out to be ...
phi = 27554341234325806742716465451216524672595447919304850637064219542729814328202676387561154175188204624894575424004190815736798277306646200007362824444984235900887686209887989471971837946286068039230967669298101493802987250668663968489404427616923945008553706682588440402642022107160279111970813001769125144160649662636192928261867108590131276295929989585771388664720943886754178869727304443592926168057522047410408181007091120781163369427915904419044794979089883778336162732163392739875336241046379767357138445037327970884254772442780284997536523900583433572282329882781376592459074913474533189565337636356492031748024
# ... Also, I encrypted a message for you:
c = 'tIya15MocbH7uxz5bz5YasIpsA8nmS+Pf41BGX2/0ioiVlLd4tRE64tboZTI0v71AWAOR5zFe7YZzc0ozSGfxBxz1UI8GitKB4JG/T1Rka0dd5gVcykXfCoUYL3uY2BxhUvytwIArXR7k4wL/fYGgu+EVeox+jvrXnkU9lc8up7s+Nr8uDr8vRxUoXKd26koJsHKFpviYNwcVjELQ6Sg6OWMuYt2wmNTfRnT2cr8lwC5dA17XoLd+f4QiF1jzJanFf+lwt4m8BW5nPfRxj5o1c3eIHO6Bz5bDYdrZeDm/s0T1SLiAU+FtjdkIYIDmBjy9QiOMgVxhKIJ2jmKDdDQ3w=='
# Let me know what you think of it! :smile:

# http://factordb.com
p = 159053155647589095148947543295873413331969384358826648953575771772292317883243422225178156162113177556876276367300742320171774708479750804793074866242471423887880626766079346938943706113589656802709292132508273728900217427551165409402265501628106343343389606578627784493206655923326362583938392325331040784069
q = n // p
assert p * q == n
assert (p-1)*(q-1) == phi

e = 0x10001

import gmpy2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import binascii
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))
key = RSA.construct((n, e, d(p,q,e)))
key = PKCS1_OAEP.new(key)
print(key.decrypt(base64.b64decode(c)).decode())
```

## In Rainbows

Stegano
Do flood-fill and read the instructions. They are plain, but hard to read optically.

![](/blog/2016/08/21/hackcon-2016/level.flood-fill.png)

``` brainfuck
++++++++[>++++>++++++>++++++++>++++++++++>++++
++++++++<<<<<-]>
>>>>++++++++++++++++++++.---------------
.<++++++++.>+++++++++++++++.<+++++++.----------.<+++.-
-.>-------.++++++.+++++++++++.>--.<<<+++.+.>>+++++.-----
.>---------.++++++++++.<<<.>>.+++.>-.<-.++++++++.>----.<---
.<<<++++++++++..>>>>---.
[>]<[[-]>]
```
