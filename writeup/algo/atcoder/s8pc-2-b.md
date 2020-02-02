---
layout: post
alias: "/blog/2016/04/23/s8pc-2-b/"
title: "square869120Contest #2 B - Division 2"
date: 2016-04-23T23:02:26+09:00
tags: [ "competitive", "writeup", "atcoder", "s8pc" ]
"target_url": [ "https://beta.atcoder.jp/contests/s8pc-2/tasks/s8pc_2_b" ]
---

## solution

逆からやる。$O(N \log N)$。

$a_i \dots a_q$による操作の後に$1$になるような($\le n$の)数の集合$S_i$を(逆から)更新していく。
初期状態の$S\_{q+1} = \\{ 1 \\}$で、$a_q \le n$なら$S_q = \\{ 1, a_q \\}$のようになる。

$S\_{i+1}$を元に$S_i$を作るわけだが、$S_i$を$a_i$で操作しても$S\_{i+1}$に一致しない可能性がある。
以下のふたつであり、それぞれ注意して処理する必要がある。

1.  $x \in S\_{i+1}$は$x a_i \in S_i$が$\frac{1}{a_i}$されて移って来たはずだが、$n \lt x a_i$なので存在しない。
2.  $x \in S\_{i+1}$は$x \in S_i$がそのまま移って来たはずが、$a_i \mid x$なので$\frac{1}{a_i}$されてしまい存在しない。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <unordered_set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    ll n; int q; cin >> n >> q;
    vector<int> a(q); repeat (i,q) cin >> a[i];
    reverse(a.begin(), a.end());
    unordered_set<ll> cur, prv;
    cur.insert(1);
    for (int ai : a) {
        cur.swap(prv);
        cur.clear();
        for (ll b : prv) {
            if (b % ai != 0) cur.insert(b);
            ll c = b * ai;
            if (c <= n) cur.insert(c);
        }
    }
    cout << cur.size() << endl;
    return 0;
}
```
