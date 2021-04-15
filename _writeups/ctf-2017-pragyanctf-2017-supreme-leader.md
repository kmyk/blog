---
layout: post
redirect_from:
  - /writeup/ctf/2017/pragyanctf-2017-supreme-leader/
  - /blog/2017/03/06/pragyanctf-2017-supreme-leader/
date: "2017-03-06T00:03:07+09:00"
tags: [ "ctf", "pragyan-ctf", "guessing" ]
---

# Pragyan CTF 2017: Supreme Leader

``` sh
$ curl -v http://139.59.62.216/supreme_leader/
*   Trying 139.59.62.216...
* Connected to 139.59.62.216 (139.59.62.216) port 80 (#0)
> GET /supreme_leader/ HTTP/1.1
> Host: 139.59.62.216
> User-Agent: curl/7.47.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Thu, 02 Mar 2017 15:55:07 GMT
< Server: Apache/2.4.7 (Ubuntu)
< X-Powered-By: PHP/5.5.9-1ubuntu4.20
< Set-Cookie: KimJongUn=2541d938b0a58946090d7abdde0d3890_b8e2e0e422cae4838fb788c891afb44f; expires=Thu, 02-Mar-2017 15:55:17 GMT; Max-Age=10
< Set-Cookie: KimJongUn=TooLateNukesGone; expires=Thu, 02-Mar-2017 15:55:18 GMT; Max-Age=10
< Vary: Accept-Encoding
< Content-Length: 1117
< Content-Type: text/html
< 
<html>
  <head>
    <title>Defense, North Korea</title>
    <link href="https://fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet">
    <style>
      body{
        background-color: #F4D03F;
        font-family: 'Open Sans', sans-serif;
        color: green;
        align: left;
      }
      .container{
        height: 300px;
        position: absolute;
        top: 120px;
        left: 10px;
      }
      h2{
        font-size: 5em;
        font-weight: lighter;
      }
    </style>
    <title>Find Me</title>
  </head>
  <body>
    <h2>North Korean Defense&nbsp;</h2>
    <div class="container">
      <p>You are accessing the super secret website of the Department of Defense, North Korea.
         Doing so without the Supreme Leader's consent is a crime and will be dealt with severely.
         Only admins are allowed to access this page after this point.
         All hail the Supreme Leader.
      </p>
      <br>
      <img src="http://images.entertainment.ie/images_content/rectangle/620x372/kju20141011228705.jpg" alt="Supreme Cookie" width="500" height="300">
    </div>
  </body>
</html>
* Connection #0 to host 139.59.62.216 left intact
```

怪しいcookie `KimJongUn=2541d938b0a58946090d7abdde0d3890_b8e2e0e422cae4838fb788c891afb44f`がある。
decrypterに投げると以下が判明する。

``` sh
$ echo -n send | md5sum
2541d938b0a58946090d7abdde0d3890  -
$ echo -n nukes | md5sum
b8e2e0e422cae4838fb788c891afb44f  -
```

よってflag: `pragyanctf{send_nukes}`。
