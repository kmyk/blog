---
layout: post
alias: "/blog/2016/08/27/icectf-2016-stage1/"
date: "2016-08-27T01:22:11+09:00"
tags: [ "ctf", "writeup", "icectf" ]
"target_url": [ "https://icec.tf/" ]
---

# IceCTF 2016: stage1

## Hello World!

`IceCTF{h3l10_wr0ld}`

## Spotlight

There is a line `console.log("DEBUG: IceCTF{5tup1d_d3v5_w1th_th31r_l095}");` in the `/spotlight.js`.

## All your Base are belong to us

Read as ascii codes written in binary number.

``` sh
$ cat flag.txt | tr ' ' '\n' | ruby -pe '$_ = $_.to_i(2).chr'
```

`IceCTF{al1_my_bases_are_yours_and_all_y0ur_bases_are_mine}`

## Rotated!

``` sh
$ alias rot13='tr A-Za-z N-ZA-Mn-za-m'
$ echo 'VprPGS{jnvg_bar_cyhf_1_vf_3?}' | rot13
IceCTF{wait_one_plus_1_is_3?}
```

## Substituted

Caesar cipher. Make the table.

```
#!/usr/bin/env python3
s = 'WvyVKT Lw wd j Gyzvecy dsbdkwksky tzjq joy vorakeqojalr jaazwvjkwemd jmu ljxy'
t = 'IceCTF Hi is a Welcome substitute flag are cryptography applications and have'
f = {}
for x, y in zip(s, t):
    if x == y == ' ':
        continue
    if x in f:
        assert f[x] == y
    f[x.lower()] = y.lower()
    f[x.upper()] = y.upper()
with open('crypted.txt') as fh:
    s = fh.read()
    print(s, end='')
    for c in s:
        if c in f:
            c = f[c]
        print(c, end='')
```

`IceCTF{always_listen_to_your_substitute_flags}`

## IRC I

Only connect the IRC server.

``` sh
$ irrsi
/connect glitch.is
/list
21:21 -!- #6470e394cb_flagshare 5 [+nt] Get your flags here! while they're hot! IceCTF{pL3AsE_D0n7_5h4re_fL495_JUsT_doNT}
```

## Alien Message

Google `alien font` for images, <https://www.google.co.jp/search?q=alien+font&tbm=isch>, and read it.

## Time Traveler

Do time travel.

<http://web.archive.org/web/20160601212948/http://time-traveler.icec.tf/>.

## Scavenger Hunt

``` sh
$ curl -s https://icec.tf/sponsors | grep 'IceCTF{.*}'
            <img class="activator" src="/static/images/logos/syndis.png" alt="IceCTF{Y0u_c4n7_533_ME_iM_h1Din9}">
```

