---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2017-qualb-c/
  - /blog/2017/11/10/code-festival-2017-qualb-c/
date: "2017-11-10T23:55:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "bipartite-graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualb/tasks/code_festival_2017_qualb_c" ]
---

# CODE FESTIVAL 2017 qual B: C - 3 Steps

## 感想

直前にICPCの練習で二部グラフに上手く落ちる問題を解いていたのですぐだった。

## solution

$G$が二部グラフなら完全二部グラフに、そうでなければ完全グラフにできる。よって二部グラフかどうか判定すればよい。$O(N + M)$。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

int check_bipartite_graph(vector<vector<int> > const & g) {
    int n = g.size();
    vector<char> used(n, -1);
    function<bool (int, int)> dfs = [&](int i, int parent) {
        for (int j : g[i]) {
            if (used[j] != -1) {
                if (used[j] == used[i]) {
                    return false;
                }
            } else {
                used[j] = used[i] ^ 1;
                if (not dfs(j, i)) return false;
            }
        }
        return true;
    };
    used[0] = 0;
    if (not dfs(0, -1)) return -1;
    return count(whole(used), 0);
}

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
    int k = check_bipartite_graph(g);
    ll result = k == -1 ?
        n *(ll) (n - 1) / 2 - m :
        k *(ll) (n - k) - m;
    // output
    printf("%lld\n", result);
    return 0;
}
```
