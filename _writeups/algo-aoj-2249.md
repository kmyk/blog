---
layout: post
redirect_from:
  - /writeup/algo/aoj/2249/
  - /blog/2017/07/04/aoj-2249/
date: "2017-07-04T20:47:52+09:00"
tags: [ "competitive", "writeup", "aoj", "jag-asia", "dijstra" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2249" ]
---

# AOJ 2249: Road Construction

やるだけって言って解いてほしい感じの問題。

## solution

最短経路に含まれる辺の中で最も安いやつだけ残す。Dijkstra。$\mathrm{ans} = \sum\_{v \ne 1} \min \\{ c(e) \| e : u \to v, d(u) + d(e) = d(v)\\}$な感じ。$O(M \log N)$。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
constexpr int inf = 1e9+7;
constexpr int root = 0;
int main() {
    while (true) {
        // input
        int n, m; scanf("%d%d", &n, &m);
        if (n == 0 and m == 0) break;
        vector<vector<tuple<int, int, int> > > g(n);
        repeat (i, m) {
            int u, v, d, c; scanf("%d%d%d%d", &u, &v, &d, &c); -- u; -- v;
            g[u].emplace_back(v, d, c);
            g[v].emplace_back(u, d, c);
        }
        // solve
        // // dijkstra
        vector<int> dist(n, inf); {
            priority_queue<pair<int, int> > que;
            dist[root] = 0;
            que.emplace(- dist[root], root);
            while (not que.empty()) {
                int cost, i; tie(cost, i) = que.top(); que.pop();
                if (dist[i] < - cost) continue;
                for (auto edge : g[i]) {
                    int j, d; tie(j, d, ignore) = edge;
                    if (- cost + d < dist[j]) {
                        dist[j] = - cost + d;
                        que.emplace(cost - d, j);
                    }
                }
            }
        }
        // // make the tree
        vector<vector<int> > h(n);
        repeat (i, n) {
            for (auto edge : g[i]) {
                int j, d, c; tie(j, d, c) = edge;
                if (dist[i] + d == dist[j]) {
                    h[j].push_back(c);
                }
            }
        }
        int result = 0;
        repeat_from (i, 1, n) {
            result += *whole(min_element, h[i]);
        }
        // output
        printf("%d\n", result);
    }
    return 0;
}
```
