---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_030/
  - /writeup/algo/atcoder/abc-030/
  - /blog/2015/10/24/abc-030/
date: 2015-10-24T23:55:58+09:00
tags: [ "abc", "atcoder", "competitive", "writeup" ]
---

# AtCoder Beginner Contest 030

A,Bはkupc後の懇親会中にスマホから、C,Dは帰路の電車内でパソコンから通した。エクストリームプログラミング

<!-- more -->

## [A - 勝率計算](https://beta.atcoder.jp/contests/abc030/tasks/abc030_a) {#a}

### 実装

整形済み (スマホから投げた時はindent幅が1だったりとかしてた)

``` python
#!/usr/bin/env python3
a,b,c,d = map(int,input().split())
t = b*c - a*d
if 0 < t:
    print('TAKAHASHI')
elif t < 0:
    print('AOKI')
else:
    print('DRAW')
```

## [B - 時計盤](https://beta.atcoder.jp/contests/abc030/tasks/abc030_b) {#b}

時針の位置は何時かだけでなく何分かにも影響されることを忘れてて手間取った。
スマホからideone使ってデバッグしてた。

### 問題

時間が与えられる。アナログ時計の時針と分針の角度を求めよ。

### 実装

整形済み

``` python
#!/usr/bin/env python3
n,m = map(int,input().split())
t = abs(n%12/12 + m/60/12 - m/60)
if t > 0.5:
    t = 1 - t
print(t * 360)
```

## [C - 飛行機乗り](https://beta.atcoder.jp/contests/abc030/tasks/abc030_c) {#c}

### 解法

貪欲

### 実装

二分探索使って実装した。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    ll x, y; cin >> x >> y;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    vector<ll> b(m); repeat (i,m) cin >> b[i];
    int k = 0;
    ll t = 0;
    while (true) {
        vector<ll> const & p = (k % 2) ? b : a;
        auto it = lower_bound(p.begin(), p.end(), t);
        if (it == p.end()) break;
        t = *it + ((k % 2) ? y : x);
        k += 1;
    }
    cout << k/2 << endl;
    return 0;
}
```

## [D - へんてこ辞書](https://beta.atcoder.jp/contests/abc030/tasks/abc030_d) {#d}

問題よく読まずに、あっこれdoublingでしょ、って言って実装したらTLEして、よく見たら$k$の上界やばくて実装し直しになった。

### 問題

関数$f : \\{1 \dots n\\} \to \\{1 \dots n\\}$が与えられる。$f^k(a)$を求めよ。ただし$k \le 10^{10^5}$。

### 解法

取り得る値の数が有限なので、十分繰り返せばループする。
つまり不動点$f^y(f^x(a)) = f^x(a)$となる$y, x \le n$がある。これを用いて$f^k(a) = f^{(k - x) \\% y}(f^x(a))$ $(k \ge y)$である。

### 実装

``` python
#!/usr/bin/env python3
n, a = map(int,input().split())
k = int(input())
b = list(map(int,input().split()))
hist = []
while a not in hist:
    hist.append(a)
    a = b[a-1]
init = hist[0 : hist.index(a)]
loop = hist[hist.index(a) : ]
if k < len(init):
    print(init[k])
else:
    print(loop[(k - len(init)) % len(loop)])
```
