---
layout: post
redirect_from:
  - /blog/2016/07/30/tenka1-2016-quala-a/
date: "2016-07-30T23:24:27+09:00"
tags: [ "competitive", "wirteup", "atcoder", "tenka1-programmer-contest" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-quala/tasks/tenka1_2016_qualA_a" ]
---

# 天下一プログラマーコンテスト2016予選A: A - 天下一プログラマーゲーム

こんなときに自作の`fizzbuzz`コマンドが便利なんですよと言いながらそれを`cp`したが、十分短いのでそんなことをする必要はなかった。

``` brainfuck
++++++++++[>+++++>+<<-]>.++++.---.-.>.
```

``` python
#!/usr/bin/env python3
ans = 0
for i in range(1,100):
    if i % 3 != 0 and i % 5 != 0:
        ans += i
print(ans)
```
