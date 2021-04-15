---
layout: post
redirect_from:
  - /writeup/algo/atcoder/codefestival-quala/
  - /blog/2015/09/26/codefestival-quala/
date: 2015-09-26T23:11:00+09:00
tags: [ "codefestival", "competitive", "atcoder", "writeup" ]
---

# CODE FESTIVAL 2015 予選A

残り1分切ってからやっと全完。
モーダル閉じたときはlast ACだったけど、十分時間開けて次見たときには残り10秒で提出してる猛者がいた。
<del> 予選Bも頑張ります。 </del> 通ってた。いえい

<!-- more -->

## [A - CODE FESTIVAL 2015](https://beta.atcoder.jp/contests/code-festival-2015-quala/tasks/codefestival_2015_qualA_a) {#a}

``` sh
sed s/2014$/2015/
```

末尾以外は`A-Z`なので`tr`でも可能らしい。

## [B - とても長い数列](https://beta.atcoder.jp/contests/code-festival-2015-quala/tasks/codefestival_2015_qualA_b) {#b}

``` python
#!/usr/bin/env python3
n = int(input())
xs = map(int,input().split())
y = 0
for x in xs:
    y = y + x + y
print(y)
```

## [C - 8月31日](https://beta.atcoder.jp/contests/code-festival-2015-quala/tasks/codefestival_2015_qualA_c) {#c}

宿題を写した時に短縮できる時間を整列し貪欲に取る。 $O(N \log N)$

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
    int n; ll t; cin >> n >> t;
    vector<int> a(n), b(n); repeat (i,n) cin >> a[i] >> b[i];
    ll y = accumulate(a.begin(), a.end(), 0ll);
    vector<int> xs(n);
    repeat (i,n) xs[i] = a[i] - b[i];
    sort(xs.rbegin(), xs.rend());
    int i = 0;
    while (i < n and y > t) y -= xs[i ++];
    cout << (y <= t ? i : -1) << endl;
    return 0;
}
```

## [D - 壊れた電車](https://beta.atcoder.jp/contests/code-festival-2015-quala/tasks/codefestival_2015_qualA_d) {#d}

ACに1時間50分を要した。

このごろ全く二分探索してなかったので存在をすっかり忘れていた。20点解法をとりあえず書いてたら思い出した。

あと実装バグらせた。
先頭の整備士が最初に右に行ってから戻ってくる場合を漏らしていた。
コードを書きながら考察が進んでいったので、古いコードが残ってしまっていて発生したバグだった。

それとは別にoverflowもさせてた。
明かに$O(M \log N)$で間に合うのに1ケースのみ`TLE`してて、何かと思ってたらoverflowだった。
でも具体的にどういう場合にoverflowするのかは不明。

## 解法

### 20点

1両目の車両が最左の整備士によって点検されることは明らかである。
すると、まず最左の整備士に関して移動の仕方を決定し、次に隣の整備士に関して、と左から順に決めていくのはよさそうに見える。

つまり、整備士の移動の仕方を左から貪欲に決定していくことを考える。
しかし、全体が塗り終わるまでの時間によって最適な動きが異なる。
よって、まず時間を固定する。
そして左から順に整備士を見ていき、どれだけ右の電車まで点検できるかを調べればよい。

$O(M N)$

### 100点

時間を二分探索する

$O(M \log N)$

## 解答

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
bool pred(ll n, ll m, vector<ll> const & xs, ll t) {
    if (t < xs[0] - 1) return false;
    ll y = 0;
    repeat (i, m) {
        if (y + t + 1 < xs[i]) {
            break;
        } else if (y + 1 < xs[i]) {
            y = max(xs[i],
                    max(y + t - ((xs[i] - y) - 2),
                        y + (xs[i] - y) + (t - (xs[i] - y) + 1) / 2));
        } else {
            y = xs[i] + t;
        }
    }
    return y >= n;
}
int main() {
    ll n, m; cin >> n >> m;
    vector<ll> xs(m); repeat (i,m) cin >> xs[i];
    ll low = -1, high = 2*n;
    while (low + 1 < high) {
        ll mid = (low + high) / 2;
        (pred(n,m,xs,mid) ? high : low) = mid;
    }
    cout << high << endl;
    return 0;
}
```

---

# CODE FESTIVAL 2015 予選A

-   Wed Sep 30 00:04:56 JST 2015
    -   結果報告
