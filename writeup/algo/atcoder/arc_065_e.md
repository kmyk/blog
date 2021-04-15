---
layout: post
date: 2018-12-07T02:45:59+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "manhattan-distance", "45-degree-rotation" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc065/tasks/arc065_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc_065_e/
  - /writeup/algo/atcoder/arc-065-e/
---

# AtCoder Regular Contest 065: E - へんなコンパス / Manhattan Compass

## 解法

### 概要

コンパスの移動可能性のグラフで連結成分をDFSで取り、その連結成分内の辺の数を数える。
$$45^\circ$$ 回転で基底変換して $$u = x + y$$ 軸と $$v = x - y$$ 軸で考える。
各行/各列ごとに点を列挙しておいてこの上で二分探索する。
連結成分を取る際には削除処理が必要で、しない場合は頂点が複数回舐められてしまうので計算量が上がる。
`std::set` や `std::map` を上手く使うと実装が楽。
$$O(N \log N)$$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
using ll = long long;

vector<bool> list_points(int n, int a, int b, vector<ll> const & x, vector<ll> const & y) {
    ll r = abs(x[a] - x[b]) + abs(y[a] - y[b]);

    // rotate 45 degrees
    map<ll, map<ll, int> > f, g;
    REP (i, n) {
        ll u = x[i] + y[i];
        ll v = x[i] - y[i];
        f[u][v] = i;
        g[v][u] = i;
    }
    auto erase = [&](int i) {
        ll u = x[i] + y[i];
        ll v = x[i] - y[i];
        f[u].erase(v);
        g[v].erase(u);
    };

    // list points
    vector<bool> used(n);
    function<void (int)> go = [&](int i) {
        ll u = x[i] + y[i];
        ll v = x[i] - y[i];
        vector<int> next;
        auto use = [&](auto first, auto last) {
            for (; first != last; ++ first) {
                next.push_back(first->second);
            }
        };
        use(f[u - r].lower_bound(v - r), f[u - r].upper_bound(v + r + 1));
        use(f[u + r].lower_bound(v - r), f[u + r].upper_bound(v + r + 1));
        use(g[v - r].lower_bound(u - r), g[v - r].upper_bound(u + r + 1));
        use(g[v + r].lower_bound(u - r), g[v + r].upper_bound(u + r + 1));
        sort(ALL(next));
        next.erase(unique(ALL(next)), next.end());
        for (int j : next) {
            assert (not used[j]);
            erase(j);
            used[j] = true;
        }
        for (int j : next) {
            go(j);
        }
    };
    erase(a);
    erase(b);
    used[a] = true;
    used[b] = true;
    go(a);
    go(b);
    return used;
}

ll count_pairs(int n, int a, int b, vector<ll> const & x, vector<ll> const & y, vector<bool> const & used) {
    ll r = abs(x[a] - x[b]) + abs(y[a] - y[b]);

    // rotate 45 degrees
    map<ll, vector<ll> > f, g;
    REP (i, n) {
        ll u = x[i] + y[i];
        ll v = x[i] - y[i];
        f[u].push_back(v);
        g[v].push_back(u);
    }
    for (auto & it : f) {
        sort(ALL(it.second));
    }
    for (auto & it : g) {
        sort(ALL(it.second));
    }

    // count pairs
    set<pair<int, int> > points;
    REP (i, n) {
        points.insert(make_pair(x[i], y[i]));
    }
    ll cnt = 0;
    REP (i, n) if (used[i]) {
        ll u = x[i] + y[i];
        ll v = x[i] - y[i];
        cnt += upper_bound(ALL(f[u - r]), v + r + 1) - lower_bound(ALL(f[u - r]), v - r);
        cnt += upper_bound(ALL(f[u + r]), v + r + 1) - lower_bound(ALL(f[u + r]), v - r);
        cnt += upper_bound(ALL(g[v - r]), u + r + 1) - lower_bound(ALL(g[v - r]), u - r);
        cnt += upper_bound(ALL(g[v + r]), u + r + 1) - lower_bound(ALL(g[v + r]), u - r);
        cnt -= points.count(make_pair(x[i] - r, y[i]));
        cnt -= points.count(make_pair(x[i] + r, y[i]));
        cnt -= points.count(make_pair(x[i], y[i] - r));
        cnt -= points.count(make_pair(x[i], y[i] + r));
    }
    return cnt / 2;
}

ll solve(int n, int a, int b, vector<ll> const & x, vector<ll> const & y) {
    return count_pairs(n, a, b, x, y, list_points(n, a, b, x, y));
}

int main() {
    int n, a, b; cin >> n >> a >> b;
    -- a; -- b;
    vector<ll> x(n), y(n);
    REP (i, n) cin >> x[i] >> y[i];
    cout << solve(n, a, b, x, y) << endl;
    return 0;
}
```
