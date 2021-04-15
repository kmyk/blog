---
layout: post
redirect_from:
  - /writeup/algo/codeforces/697-c/
  - /blog/2016/07/15/cf-697-c/
date: "2016-07-15T04:00:25+09:00"
tags: [ "competitive", "writeup", "codeforces", "tree" ]
"target_url": [ "http://codeforces.com/contest/697/problem/C" ]
---

# Codeforces Round #362 (Div. 2) C. Lorenzo Von Matterhorn

## problem

根付き木が与えられる。
頂点には番号が降ってあり、$1$が根であり、$i$番目と$2i, 2i+1$番目の頂点との間に辺がある。頂点は十分な数あると考えてよい。
以下のクエリに答えよ。

-   頂点$v, u$を結ぶ唯一の道上の辺の重みを$w$増加させる。
-   頂点$v, u$を結ぶ唯一の道上の辺の重みの総和を出力する。

指定される頂点$1 \le v, u \le 10^{18}$である。

## solution

Simply implement it. $O(q (\log v + \log u))$.

The tree depth is not large, at most $\log 10^{18} \approx 60$.
So the number of involved vertices is bounded $q \cdot 2 \cdot 60 \le 120000$.
This is a small number, so the naive implementation can be enough.

## implementation

``` c++
#include <cstdio>
#include <unordered_map>
#include <functional>
typedef long long ll;
using namespace std;
void query(ll a, ll b, function<void (ll)> cont) {
    if (a < b) {
        cont(b);
        query(a, b/2, cont);
    } else if (a > b) {
        cont(a);
        query(a/2, b, cont);
    }
}
int main() {
    unordered_map<ll,ll> fee;
    int q; scanf("%d", &q);
    while (q --) {
        int t; scanf("%d", &t);
        if (t == 1) {
            ll a, b, c;
            scanf("%I64d%I64d%I64d", &a, &b, &c);
            query(a, b, [&](ll i) { fee[i] += c; });
        } else if (t == 2) {
            ll a, b;
            scanf("%I64d%I64d", &a, &b);
            ll c = 0;
            query(a, b, [&](ll i) { c += fee[i]; });
            printf("%I64d\n", c);
        }
    }
    return 0;
}
```
