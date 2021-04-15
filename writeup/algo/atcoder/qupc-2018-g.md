---
redirect_from:
layout: post
date: 2018-10-25T14:23:31+09:00
tags: [ "competitive", "writeup", "atcoder", "graph", "tree-dp", "fold" ]
"target_url": [ "https://beta.atcoder.jp/contests/qupc2018/tasks/qupc2018_g" ]
---

# 九州大学プログラミングコンテスト2018: G - Tapu &amp; Tapi 2

## 解法

### 概要

木DP。
各部分木について根を含む連結成分に「たぷを含むよう切るときの最小コスト」「たぴを含むよう切るときの最小コスト」「どちらも含まないように切るときの最小コスト」を求める。
$O(N)$。

## メモ

-   手癖でACすると解説読んだ後「なるほど私の実装はそういう意味だったのかあ」になりがち
-   部分点は最小カット

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <class T, class U> inline void chmin(T & a, U const & b) { a = min<T>(a, b); }

struct node_t {
    ll cost_p, cost_q, cut;
};

ll solve(int n, int x, int y, vector<vector<pair<int, int> > > const & g, vector<char> const & type) {
    constexpr ll INF = (ll)1e18 + 9;
    function<node_t (int, int)> go = [&](int i, int parent) {
        node_t cur = {};
        cur.cut = INF;
        for (auto edge : g[i]) {
            int j; ll cost; tie(j, cost) = edge;
            if (j == parent) continue;
            node_t prv = go(j, i);
            cur.cost_p += min(prv.cost_p, prv.cost_q + min(cost, prv.cut));
            cur.cost_q += min(prv.cost_q, prv.cost_p + min(cost, prv.cut));
            cur.cut = min(INF, cur.cut + prv.cut);
        }
        if (type[i] == 'P') cur.cost_q = cur.cut = INF;
        if (type[i] == 'Q') cur.cost_p = cur.cut = INF;
        return cur;
    };
    node_t cur = go(0, -1);
    return min(cur.cost_p, cur.cost_q);
}

int main() {
    int n, x, y; cin >> n >> x >> y;
    vector<vector<pair<int, int> > > g(n);
    REP (i, n - 1) {
        int a, b, v; cin >> a >> b >> v;
        -- a; -- b;
        g[a].emplace_back(b, v);
        g[b].emplace_back(a, v);
    }
    vector<char> type(n);
    REP (i, x) {
        int p; cin >> p; -- p;
        type[p] = 'P';
    }
    REP (i, y) {
        int q; cin >> q; -- q;
        type[q] = 'Q';
    }
    cout << solve(n, x, y, g, type) << endl;
    return 0;
}
```
