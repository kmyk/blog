---
layout: post
alias: "/blog/2017/11/26/cf17-final-a/"
date: "2017-11-26T10:02:20+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "regexp" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-final-open/tasks/cf17_final_a" ]
---

# CODE FESTIVAL 2017 Final: A - AKIBA

## solution

(丁寧に)やるだけ。選択肢はいくつかある:

-   正規表現
-   $S$と`AKIHABARA`を両方一緒になめていく
-   `AKIHABARA`から`A`をいくつか除いたものを全列挙して等号比較

## 感想

Aのくせに面倒だなあと思ったけどそのまま書いてしまった。正規表現なら秒なので気付きたかった。

## implementation

``` python
#!/usr/bin/env python3
def solve(s):
    i = 0
    for c in 'AKIHABARA':
        if i < len(s) and c == s[i]:
            i += 1
        elif c == 'A':
            pass
        else:
            return False
    if i != len(s):
        return False
    return True
print(['NO', 'YES'][solve(input())])
```
