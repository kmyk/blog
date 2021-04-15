---
layout: post
redirect_from:
  - /writeup/algo/atcoder/cf17-relay-d/
  - /blog/2017/11/27/cf17-relay-d/
date: "2017-11-27T17:58:10+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "team-relay", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-relay-open/tasks/relay2_d" ]
---

# Code Festival Team Relay: D - Shock

## solution

連結成分に分解し、$1, 2$を含むもののうち大きい方に全て寄せる。
完全グラフの辺の数は頂点数の$2$乗のオーダーなため。
$O(N)$。

## implementation

``` c++
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<int> > g(n);
    repeat (i, m) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // solve
    vector<char> used(n);
    function<int (int)> go = [&](int i) {
        used[i] = true;
        int cnt = 1;
        for (int j : g[i]) if (not used[j]) {
            cnt += go(j);
        }
        return cnt;
    };
    ll k0 = go(0);
    ll k1 = go(1);
    if (k0 > k1) swap(k0, k1);
    k1 += (n - k0 - k1);
    ll result = k0 * (k0 - 1) / 2 + k1 * (k1 - 1) / 2 - m;
    // output
    printf("%lld\n", result);
    return 0;
}
```
