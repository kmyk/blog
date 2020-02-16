---
layout: post
redirect_from:
  - /blog/2017/11/27/cf17-relay-e/
date: "2017-11-27T17:58:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "team-relay" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-relay-open/tasks/relay2_e" ]
---

# Code Festival Team Relay: E - White and Blue

Fより難しい

## solution

有理式をなくして考えるのがポイント。$O(N \log N)$。

混乱を防ぐため白票は$a\_i = w\_i$とする。
投票された白票青票の総数をそれぞれ$A, B$とすると、$\frac{A}{A + B} \ge \frac{P}{100}$にすればよい。
式変形をすると$(100 - P)A - PB \ge 0$。
($\frac{A}{A + B}$を最大化するのではなく、同じではあるが)$(100 - P)A - PB$を最大化することを考える。
これは単に$(100 - P)a\_i - pb\_i$の値でsortして上から順に取ればよい。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <numeric>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int n, p; scanf("%d%d", &n, &p);
    vector<ll> a(n), b(n); repeat (i, n) scanf("%lld%lld", &a[i], &b[i]);
    // solve
    vector<int> order(n);
    iota(whole(order), 0);
    int result = 0;
    ll aa = 0, bb = accumulate(whole(b), 0ll);
    sort(whole(order), [&](int i, int j) {
        return (100 - p) * a[i] + p * b[i] > (100 - p) * a[j] + p * b[j];
    });
    for (int i : order) {
        aa += a[i];
        bb -= b[i];
        result += 1;
        if ((100 - p) * aa >= p * bb) break;
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
