---
layout: post
redirect_from:
  - /blog/2016/09/25/code-festival-2016-quala-c/
date: "2016-09-25T03:26:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-quala/tasks/codefestival_2016_qualA_c" ]
---

# CODE FESTIVAL 2016 qual A: C - 次のアルファベット / Next Letter

辞書順最小を作るので、先頭の文字から`a`にできるか見ていく。触ると悪化するなら無視。全部舐めて$k$が余ったら末尾の文字に使う。

``` python
#!/usr/bin/env python3
s = input()
k = int(input())
t = list(map(lambda c: ord(c)-ord('a'), s))
for i in range(len(t)):
    if t[i] != 0 and 26-t[i] <= k:
        k -= 26-t[i]
        t[i] = 0
if k:
    t[i] = (t[i]+k) % 26
    k = 0
ans = ''.join(map(lambda c: chr(c+ord('a')), t))
print(ans)
```
