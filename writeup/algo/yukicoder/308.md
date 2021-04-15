---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/308/
  - /blog/2015/12/03/yuki-308/
date: 2015-12-03T00:56:46+09:00
tags: [ "yukicoder", "competitive", "writeup", "prime", "miller-rabin" ]
---

# Yukicoder No.308 素数は通れません

[Advent Calendar Contest Advent Calendar 2015](http://www.adventar.org/calendars/912)の1日目。

観察と数学をする問題。
あまり簡単ではないが、そこまで難しくもない。
なにやら怪しげな解法を生やしていたら通った。

最初のAC提出は`subprocess`から`factor(1)`を叩いていたが、作者による解説にて[miller-rabin素数判定法](https://ja.wikipedia.org/wiki/%E3%83%9F%E3%83%A9%E3%83%BC%E2%80%93%E3%83%A9%E3%83%93%E3%83%B3%E7%B4%A0%E6%95%B0%E5%88%A4%E5%AE%9A%E6%B3%95)が言及されていたので写経して提出し直した。

<!-- more -->

## [No.308 素数は通れません](http://yukicoder.me/problems/840)

### 問題

$1$から$N$までの自然数を一列に並べ幅$W$で折り返してできるような表を考える。
そのような表の上で、自然数$1$のマスから$N$のマスまで、素数の書かれたマスを通らないように移動したい。
合成数$N \le 10^{24}$が与えられるので、そのような移動が可能な$W$で最小のものを出力せよ。

### 解法

幅$W$で折り返したとき、一番上の行に$W$の約数の数が書かれた列は、一番上の行を除いて全て素数ではない。表を書けば気付ける。
ほとんどの数に関して、$W = 8$が答えになることが予想できる。

ただし以下のような例が問題となる。例えば$W = 8$であるとき、素数$p$に対し$p+8$と表せる数の場合、表に$p+9$は存在しないため、明らかに到達できない。これは弾かなければならない。

``` plain
1       2       3       4       5       6       7       8
...
p       p+1     p+2     p+3     p+4     p+5     p+6     p+7
p+8
```

この問題を解決するには、$N$が小さく愚直に探索できる場合は探索、$N$が大きいときはある種のヒューリスティックな発想を用いる。
つまり、$N$が十分大きいとき表の中には合成数がかなり多いので、$1$の付近と$N$の付近だけ確認すればよい。
また、$N \le 10^{24}$の制約から、高速な素数判定アルゴリズムが必要である。
これを適当に書けば通る。


数学を使ってきちんと解くときの解説は作者によるものがある。
答えの$W$が$14$を越えることがないことが言われている。

-   [No.308 素数は通れません 解説](http://yukicoder.me/problems/840/editorial)

### 反省

-   素数$p+W$で表される数がコーナーになることを、WA生やすまで気付けなかった。
-   数学でやれば綺麗。途中までそのようなことはしたのに、不注意から、$W$はいくらでも大きくなりうるという間違った結論を出してしまった。

### 実装

解法の選択が悪く、冗長なものになっている。

``` python
#!/usr/bin/env python3
import random
def is_prime(n, k=20): # miller-rabin primality test
    if n == 2:
        return True
    if n == 1 or n % 2 == 0:
        return False
    d = n - 1
    while d % 2 == 0:
        d //= 2
    for _ in range(k):
        a = random.randint(1,n-2)
        t = d
        y = pow(a,t,n)
        while t != n-1 and y != 1 and y != n-1:
            y = (y * y) % n
            t <<= 1
        if y != n-1 and t & 1 == 0:
            return False
    return True
def bfs(n, w, initial, accept, deny=None):
    que = [initial]
    i = 0
    pushed = set(que)
    while i < len(que):
        if accept(que, i):
            return True
        if deny is not None and deny(que, i):
            return False
        x = que[i]
        i += 1
        def f(y):
            if y not in pushed and not is_prime(y):
                que.append(y)
                pushed.add(y)
        if x-1 >  0 and x % w != 1: f(x-1)
        if x+1 <= n and x % w != 0: f(x+1)
        if x-w >  0:                f(x-w)
        if x+w <= n:                f(x+w)
def solve(n):
    if n < 300: # magic number
        for w in range(1,n):
            if bfs(n, w, 1, lambda que, i: que[i] == n):
                return w
    else:
        for w in range(2,n):
            if bfs(n, w, 1, lambda que, i: que[i] % w == 0) \
                    and bfs(n, w, n, lambda que, i: len(que) >= 10): # magic number
                return w
print(solve(int(input())))
```

---

# Yukicoder No.308 素数は通れません

-   Mon Feb  1 00:45:47 JST 2016
    -   自分で再実装していた累乗を組込みの`pow`で置換
