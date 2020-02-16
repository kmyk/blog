---
layout: post
alias: "/blog/2017/10/22/kupc-2017-h/"
date: "2017-10-22T13:33:31+09:00"
tags: [ "competitive", "writeup", "kupc", "atcoder", "flow", "maximum-flow", "dinic", "linear-programming" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_h" ]
---

# Kyoto University Programming Contest 2017: H - Make a Potion

私のライブラリのdinicは遅いという疑惑が浮上している。そのうち直す。そのうち。

## solution

最小cut。$O(V^2E)$。

下図みたいなネットワークを作る。$h\_i = 2$の側で$200l$以上使ったら$h\_j = -1$のを$400l$使わないといけない場合の例。
始点 $\to$ ($h\_i \gt 0$な頂点群) $\leftrightarrow$ ($h\_i \le 0$な頂点群) $\to$ 終点。
$h\_i \gt 0$については最初に$\sum h\_i v\_i$を足しておいて、そこからcutの結果を引く。

```
    -------------------------------------------------+---------------------> dst
                                                     ^  600
                                                     |
                         300l                      600l
                     200  ^|                        |^  400
                          |v  inf     inf      inf  v|
                         200l -------------------> 400l
                     202  ^|                        |^   0
                          |v  inf              inf  v|
                         199l                       0l (h_j = -1)
                     600  ^|
                          |v  inf
                          0l (h_i = +2)
                     inf  ^
                          |
src ----------------------+------------------------------------------------>
```

明らかに線形計画問題で定式化できるが、それを足場とすれば思い付きやすい。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <queue>
#include <unordered_map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

uint64_t pack(int i, int j) {
    return (uint64_t(i) << 32) | j;
}

ll maximum_flow(int s, int t, int n, unordered_map<uint64_t, ll> & capacity /* adjacency matrix */) { // dinic, O(V^2E)
    auto residue = [&](int i, int j) { auto key = pack(i, j); return capacity.count(key) ? capacity[key] : 0; };
    vector<vector<int> > g(n); repeat (i,n) repeat (j,n) if (residue(i, j) or residue(j, i)) g[i].push_back(j); // adjacency list
    ll result = 0;
    while (true) {
        vector<int> level(n, -1); level[s] = 0;
        queue<int> q; q.push(s);
        for (int d = n; not q.empty() and level[q.front()] < d; ) {
            int i = q.front(); q.pop();
            if (i == t) d = level[i];
            for (int j : g[i]) if (level[j] == -1 and residue(i,j) > 0) {
                level[j] = level[i] + 1;
                q.push(j);
            }
        }
        vector<bool> finished(n);
        function<ll (int, ll)> augmenting_path = [&](int i, ll cur) -> ll {
            if (i == t or cur == 0) return cur;
            if (finished[i]) return 0;
            finished[i] = true;
            for (int j : g[i]) if (level[i] < level[j]) {
                ll f = augmenting_path(j, min(cur, residue(i,j)));
                if (f > 0) {
                    capacity[pack(i, j)] -= f;
                    capacity[pack(j, i)] += f;
                    finished[i] = false;
                    return f;
                }
            }
            return 0;
        };
        bool cont = false;
        while (true) {
            ll f = augmenting_path(s, numeric_limits<ll>::max());
            if (f == 0) break;
            result += f;
            cont = true;
        }
        if (not cont) break;
    }
    return result;
}

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> v(n); repeat (i, n) scanf("%d", &v[i]);
    vector<int> h(n); repeat (i, n) scanf("%d", &h[i]);
    vector<tuple<int, int, int, int> > constraints(m);
    repeat (i, m) {
        int a, x, b, y; scanf("%d%d%d%d", &a, &x, &b, &y); -- a; -- b;
        constraints[i] = { a, x, b, y };
    }

    // solve
    // // collect vertices
    constexpr int V_FREE = 0;
    constexpr int V_OUT = 0;
    constexpr int V_CEIL = 1;
    constexpr int V_IN = 2;
    vector<vector<pair<int, int> > > border(n);
    for (auto constraint : constraints) {
        int a, x, b, y; tie(a, x, b, y) = constraint;
        if (x - 1 >= 0) border[a].emplace_back(x - 1, V_CEIL);
        border[a].emplace_back(x, V_OUT);
        border[b].emplace_back(y, V_IN);
    }
    repeat (i, n) {
        border[i].emplace_back(0, V_FREE);
        border[i].emplace_back(v[i], V_FREE);
        sort(whole(border[i]));
        vector<pair<int, int> > nborder;
        for (auto it : border[i]) {
            int z, type; tie(z, type) = it;
            if (not nborder.empty() and nborder.back().first == z) {
                nborder.back().second |= type;
            } else {
                nborder.emplace_back(z, type);
            }
        }
        border[i] = nborder;
        nborder.clear();
        for (auto it : border[i]) {
            int z, type; tie(z, type) = it;
            if (h[i] > 0) {
                if (z == v[i] or (type & V_CEIL)) {
                    nborder.emplace_back(z, type);
                }
            } else {
                if (z == 0 or (type & V_IN)) {
                    nborder.emplace_back(z, type);
                }
            }
        }
        border[i] = nborder;
    }
    // // make the graph
    unordered_map<uint64_t, int> index;
    repeat (i, n) {
        for (auto it : border[i]) {
            int z = it.first;
            index.emplace(pack(i, z), index.size());
        }
    }
    unordered_map<uint64_t, ll> capacity;
    const int src = index.size();
    const int dst = index.size() + 1;
    constexpr ll inf = ll(1e18)+7;
    repeat (i, n) {
        capacity[pack(src, index[pack(i, border[i][0].first)])] = inf;
        repeat (j, border[i].size() - 1) {
            int z = border[i][j + 1].first;
            int pz = border[i][j].first;
            int w = z - pz;
            if (h[i] > 0) {
                capacity[pack(src, index[pack(i, z)])] = w *(ll) h[i];
            } else {
                capacity[pack(index[pack(i, z)], dst)] = w *(ll) abs(h[i]);
            }
            capacity[pack(index[pack(i, z)], index[pack(i, pz)])] = inf;
        }
    }
    for (auto constraint : constraints) {
        int a, x, b, y; tie(a, x, b, y) = constraint;
        auto it = lower_bound(whole(border[a]), make_pair(x, 0));
        if (it == border[a].end()) { assert (h[a] <= 0); continue; }
        x = it->first;
        y = lower_bound(whole(border[b]), make_pair(y, 0))->first;
        capacity[pack(index[pack(a, x)], index[pack(b, y)])] = inf;
    }
    // // run dinic
    ll sum_positive = 0;
    repeat (i, n) {
        if (h[i] > 0) {
            sum_positive += v[i] *(ll) h[i];
        }
    }
    ll result = sum_positive - maximum_flow(src, dst, index.size() + 2, capacity);

    // output
    printf("%lld\n", result);
    return 0;
}
```
