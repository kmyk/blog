---
layout: post
redirect_from:
  - /writeup/algo/codeforces/615-b/
  - /blog/2016/01/09/cf-615-b/
date: 2016-01-09T01:20:09+09:00
tags: [ "competitive", "writeup", "codeforces", "graph", "dp" ]
---

# Codeforces Round #338 (Div. 2) B. Longtail Hedgehog

この回の他の問題の問題文はかなり読みやすいにもかかわらず、この問題だけ英語の問題だった。

## [B. Longtail Hedgehog](http://codeforces.com/contest/615/problem/B) {#b}

### 問題

単純グラフが与えられる。
この単純グラフ上の向き付けられた道で、その道上の頂点のindexが単調増加なものに関して、次のように点数を定めるとき、その最大値を答えよ。

-   道の端点でindexが大きい方の次数を$d$とし、道の長さを$l$としたとき、点数は$dl$

### 解法

各頂点に関してそれを尻尾の端点としたときにできる尾の長さの最大値を求めればよい。
普通のdp。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<vector<int> > g(n);
    repeat (i,m) {
        int u, v; cin >> u >> v; -- u; -- v;
        g[u].push_back(v);
        g[v].push_back(u);
    }
    vector<int> dp(n, 1);
    repeat (i,n) {
        for (int j : g[i]) if (i < j) {
            dp[j] = max(dp[j], dp[i] + 1);
        }
    }
    ll ans = 0;
    repeat (i,n) ans = max(ans, ll(g[i].size()) * dp[i]);
    cout << ans << endl;
    return 0;
}
```
