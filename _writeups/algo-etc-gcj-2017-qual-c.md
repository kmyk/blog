---
layout: post
redirect_from:
  - /writeup/algo/etc/gcj-2017-qual-c/
  - /blog/2017/04/10/gcj-2017-qual-c/
date: "2017-04-10T02:45:08+09:00"
tags: [ "competitive", "writeup", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/3264486/dashboard#s=p2" ]
---

# Google Code Jam Qualification Round 2017: C. Bathroom Stalls

## solution

座標は答えなくていいことに注意して、区間の列を操作していく。だいたい$O(\log N)$。

長さ$N$の区間を$1$個queueに入れた状態から始めて、
最も大きい区間を長さ$n$としてこれが$k$個あるとき、これらをqueueから取り出して代わりに長さ$\lceil \frac{n-1}{2} \rceil, \r \frac{n-1}{2} \rceil$の区間をそれぞれ$k$個ずつ入れるというのを繰り返せばよい。
同じ長さの区間をきちんとまとめれば$O(\log N)$程度になるので間に合う。

## implementation

``` c++
#include <cstdio>
#include <map>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
pair<ll, ll> solve(ll n, ll k) {
    map<ll, ll> que;
    que.emplace(n, 1);
    while (true) {
        ll len, cnt; tie(len, cnt) = *que.rbegin(); que.erase(len);
        ll l = (len - 1) / 2;
        ll r = (len - 1 + 1) / 2;
        que[l] += cnt;
        que[r] += cnt;
        k -= cnt;
        if (k <= 0) {
            return make_pair(r, l);
        }
    }
}
int main() {
    int t; scanf("%d", &t);
    repeat (x,t) {
        ll n, k; scanf("%lld%lld", &n, &k);
        ll y, z; tie(y, z) = solve(n, k);
        printf("Case #%d: %lld %lld\n", x+1, y, z);
    }
    return 0;
}
```
