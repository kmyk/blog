---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/349/
  - /blog/2016/03/11/yuki-349/
date: 2016-03-11T23:06:09+09:00
tags: [ "competitive", "writeup", "yukicoder", "golf" ]
---

# Yukicoder No.349 干支の置き物

`++ $$_` is 何。

## [No.349 干支の置き物](http://yukicoder.me/problems/924)

### 実装

#### perl 75byte

``` perl
$n=<>;chop,$a{$_}++for<>;@a=sort{$b-$a}values%a;print$n>2*$a[0]-2?YES:NO,$/
```

辞書に入れて数え`values`を降順に`sort`して式。

#### 非golf

``` python
#!/usr/bin/env python3
n = int(input())
f = {}
for _ in range(n):
    a = input()
    if a not in f:
        f[a] = 0
    f[a] += 1
k = max(f.values())
print(2*(k-1) < n and 'YES' or 'NO')
```

### 解読

tails氏 perl 43byte

``` perl
<>;@a=<>;print grep(@a<2*++$$_-1,@a)?NO:YES
```

1行目$N$は捨て、残りを配列`@a`に入れる。`grep(@a<2*++$$_-1,@a)`で判定。$N$は`@a`で取れて、`$$_`は[dereference](http://stackoverflow.com/questions/22619917/perl-var-two-dollar-signs-as-a-sigil)らしい。`$_`は普通の文字列だけど、`$$_`は何？ 初期値は`1`で、`++ $$_`とすることで$k$回目の$A_i$の出現の際に`++ $$_`は整数$k$になるようだが。
