---
layout: post
alias: "/blog/2017/09/20/ekoparty-ctf-2017-malbolge/"
date: "2017-09-20T20:38:24+09:00"
tags: [ "ctf", "writeup", "misc", "ekoparty-ctf", "malbolge" ]
---

# EKOPARTY CTF 2017: Shopping

まさかhelloworld出力して終わりとは思わなかった。悲しい。

## problem

`Welcome to EKOPARTY!`と出力するmalbolgeのプログラムを書け。

## solution

<http://shinh.hatenablog.com/entry/20121210/1355068468> これを読んで探索する。

```
$ nc malbolge.ctf.site 40111
Send a malbolge code that print: 'Welcome to EKOPARTY!' (without single quotes)
ba&%$#8=~}4{WDxfAut+qqL'9m7jjihgfA@cxw<_z\\[6YXm!UT0RglOwvL'fIHcFa`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@9]~6Z43Wx0Tu-Qr*Non&Jk#"Fg}C{z@awv<]sr8Yo5VUk1Rh.Oe+Lb(`_%F\"CB}j
Running code...
Welcome to EKOPARTY!
Your flag is: EKO{0nly4nother3soteric1anguage}
```

## implementation

``` python
#!/usr/bin/env python3
import malbolge  # https://github.com/kmyk/malbolge-interpreter/blob/be70bf495b16044c07a50c3bfa8e391805637aa7/a.py
import queue
import io

def decrypt1(code):
    return ''.join(malbolge.decrypt1(i, c) for i, c in enumerate(code))
def run(code):
    code = decrypt1(code)
    inf = io.BytesIO(b'')
    outf = io.BytesIO()
    malbolge.execute(code.encode(), inf=inf, outf=outf)
    return outf.getvalue()

target = b'Welcome to EKOPARTY!' # => ba&%$#8=~}4{WDxfAut+qqL'9m7jjihgfA@cxw<_z\\[6YXm!UT0RglOwvL'fIHcFa`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@9]~6Z43Wx0Tu-Qr*Non&Jk#"Fg}C{z@awv<]sr8Yo5VUk1Rh.Oe+Lb(`_%F\"CB}j

que = queue.deque()
que.append({ 'data': '', 'code': '' })
def to_code(obj):
    return 'i' + obj['data'] + 'o' * (98 - len(obj['data'])) + obj['code'] + 'v'
for i in range(len(target)):
    while que:
        obj = que.popleft()
        obj['output'] = run(to_code(obj))
        print(obj)
        if obj['output'] == target[: i + 1]:
            que = queue.deque()
            que.append(obj)
            break
        elif obj['output'] == target[: i]:
            for d in 'ji*p</vo':
                for c in '*p<':
                    que.append({ 'data': obj['data'] + d, 'code': obj['code'] + c })
print(to_code(obj))
print(decrypt1(to_code(obj)))
```
