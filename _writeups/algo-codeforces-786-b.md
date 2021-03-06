---
layout: post
redirect_from:
  - /writeup/algo/codeforces/786-b/
  - /blog/2017/03/24/cf-786-b/
date: "2017-03-24T02:00:20+09:00"
tags: [ "competitive", "writeup", "codeforces", "segment-tree", "graph", "dijkstra" ]
"target_url": [ "http://codeforces.com/contest/786/problem/B" ]
---

# Codeforces Round #406 (Div. 1): B - Legacy

`vector<vector<int, ll> >`でグラフを取って`priority_queue<pair<ll, int> >`でdijkstraしたら`tie`するときに順序を間違えて時間を溶かした。

## problem

以下からなるクエリ列で説明される有向グラフ$G$が与えられる。頂点$s$からの各頂点への距離を求めよ。

1.  頂点$v, u$間にコスト$w$の辺$v \to u$がある
2.  頂点$v$と区間$[l, r]$中の任意の頂点$u \in [l, r]$にコスト$w$の辺$v \to u$がある
3.  頂点$v$と区間$[l, r]$中の任意の頂点$u \in [l, r]$にコスト$w$の辺$u \to v$がある

## solution

グラフの頂点をsegment木で管理するテク。$E = Q \log N, \; V = N \log N$として$O(E \log V)$。

区間クエリが入るものと出るものの$2$種類あるので、segment木を$2$本立てて対応する葉は融合させる。
後はdijkstraすればよい。

konjoさんによる分かりやすい図: <https://twitter.com/konjo_p/status/844958629392408576>。

## implementation

よくあるテクそのままという感じだけど始めて書いた。
終了後のTLでは面倒実装なだけでつまらんとの不評が多かった。

``` c++
#include <cstdio>
#include <vector>
#include <queue>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int original_n, q, start; scanf("%d%d%d", &original_n, &q, &start); -- start;
    // prepare a graph
    int n = 1 << (32 - __builtin_clz(original_n - 1));
    vector<vector<pair<int, int> > > g(n + n-1 + n-1);
    const int src = n;
    const int dst = n + n-1;
    auto coalesce = [&](int i, int base) { assert (i < 2*n-1); return i < n-1 ? base + i : i - (n-1); };
    repeat (i,n-1) {
        int l = 2*i+1;
        int r = 2*i+2;
        g[src + i].emplace_back(coalesce(l, src), 0);
        g[src + i].emplace_back(coalesce(r, src), 0);
        g[coalesce(l, dst)].emplace_back(dst + i, 0);
        g[coalesce(r, dst)].emplace_back(dst + i, 0);
    }
    // add edges
    while (q --) {
        int type; scanf("%d", &type);
        if (type == 1) {
            int v, u, cost; scanf("%d%d%d", &v, &u, &cost); -- v; -- u;
            g[v].emplace_back(u, cost);
        } else if (type == 2) {
            int v, l, r, cost; scanf("%d%d%d%d", &v, &l, &r, &cost); -- v; -- l;
            for (l += n, r += n; l < r; l /= 2, r /= 2) {
                if (l % 2 == 1) g[v].emplace_back(coalesce((l ++) - 1, src), cost);
                if (r % 2 == 1) g[v].emplace_back(coalesce((-- r) - 1, src), cost);
            }
        } else if (type == 3) {
            int v, l, r, cost; scanf("%d%d%d%d", &v, &l, &r, &cost); -- v; -- l;
            for (l += n, r += n; l < r; l /= 2, r /= 2) {
                if (l % 2 == 1) g[coalesce((l ++) - 1, dst)].emplace_back(v, cost);
                if (r % 2 == 1) g[coalesce((-- r) - 1, dst)].emplace_back(v, cost);
            }
        }
    }
    // dijkstra
    vector<ll> dist(n + n-1 + n-1, inf);
    priority_queue<pair<ll, int> > que;
    dist[start] = 0;
    que.emplace(- dist[start], start);
    while (not que.empty()) {
        ll cost; int i; tie(cost, i) = que.top(); que.pop();
        if (dist[i] < - cost) continue;
        for (auto it : g[i]) {
            int j; ll delta; tie(j, delta) = it;
            if (- cost + delta < dist[j]) {
                dist[j] = - cost + delta;
                que.emplace(cost - delta, j);
            }
        }
    }
    // output
    repeat (i,original_n) {
        if (i) printf(" ");
        printf("%lld", dist[i] == inf ? -1 : dist[i]);
    }
    printf("\n");
    return 0;
}
```
