---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/548/
  - /blog/2017/07/29/yuki-548/
date: "2017-07-29T00:10:09+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "https://yukicoder.me/problems/no/548" ]
---

# Yukicoder No.548 国士無双

## solution

実装するだけ。

使われてない単語の種類数を数えて$0$か$1$かそれ以外とするとよい。

## implementation

``` python
#!/usr/bin/env python3
t = 'abcdefghijklm'
s = input()
result = 'Impossible'
if sorted(s) == list(t):
    result = '\n'.join(list(t))
else:
    if len(s) == len(t):
        unused = ''
        for c in t:
            if c not in s:
                unused += c
        if len(unused) == 1:
            result = unused
print(result)
```
