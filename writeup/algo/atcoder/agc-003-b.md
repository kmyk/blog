---
layout: post
redirect_from:
  - /blog/2016/08/21/agc-003-b/
date: "2016-08-21T23:55:19+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc003/tasks/agc003_b" ]
---

# AtCoder Grand Contest 003 B - Simplified mahjong

## solution

貪欲。$O(N)$。

差を見るので、整列して順に見ていけばよいのはすぐに分かる。
$A\_{i-1} = 0$と見なせるとき$i$に着目して、組$(i, i)$と組$(i, i+1)$のどちらをどれだけ作るべきかを考える。消費枚数が同じなのと、カード$i$はこれ以外に使い道がないことから、組$(i, i)$を可能な限り作るのがよい。カード$i+1$のことを考えると、カード$i$が余ったならとりあえず組$(i, i+1)$を作るのがよい。この貪欲で答えが求まる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    ll ans = 0;
    repeat (i,n) {
        ans += a[i] / 2;
        a[i] %= 2;
        if (i+1 < n) {
            int d = min(a[i], a[i+1]);
            a[i  ] -= d;
            a[i+1] -= d;
            ans    += d;
        }
    }
    printf("%lld\n", ans);
    return 0;
}
```
