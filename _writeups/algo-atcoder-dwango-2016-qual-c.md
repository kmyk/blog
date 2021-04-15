---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwango-2016-qual-c/
  - /blog/2016/01/23/dwango-2016-qual-c/
date: 2016-01-23T22:12:19+09:00
tags: [ "competitive", "writeup", "atcoder", "dwango", "dijkstra", "binary-search" ]
---

# 第2回 ドワンゴからの挑戦状 予選 C - メンテナンス明け

解けず。この手の二分法を思い付くのまだ苦手。

## [C - メンテナンス明け](https://beta.atcoder.jp/contests/dwango2016-prelims/tasks/dwango2016qual_c)

### 解説

移動時間の制限を決めると、寝過しの発生が辺の使用の制約に変わるので、これで二分探索。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct edge_t { int to; ll cost; int terminal; ll cost_to_terminal; };
struct state_t { int i; ll cost; };
bool operator < (state_t a, state_t b) { return a.cost > b.cost; }
int main() {
    int n, m, src, dst; cin >> n >> m >> src >> dst;
    vector<vector<edge_t> > g(n);
    repeat (i,m) {
        int l; cin >> l;
        vector<int> s(l); repeat (j,l) cin >> s[j];
        vector<ll> w(l-1); repeat (j,l-1) cin >> w[j];
        ll total = accumulate(w.begin(), w.end(), 0ll);
        ll acc = 0;
        repeat (j,l-1) {
            g[s[j  ]].push_back((edge_t) { s[j+1], w[j], s.back(), total-acc });
            acc += w[j];
            g[s[j+1]].push_back((edge_t) { s[j  ], w[j], s.front(), acc });
        }
    }
    vector<ll> dist(n, -1); {
        priority_queue<state_t> q; // dijkstra from dst
        q.push((state_t) { dst, 0 });
        while (not q.empty()) {
            state_t s = q.top(); q.pop();
            if (dist[s.i] != -1) continue;
            dist[s.i] = s.cost;
            for (edge_t e : g[s.i]) if (dist[e.to] == -1) {
                q.push((state_t) { e.to, s.cost + e.cost });
            }
        }
    }
    ll low = -1, high = 1e18; // (low, high]
    while (low + 1 < high) { // binary-search
        ll mid = (low + high) / 2;
        vector<ll> sdist(n, -1);
        priority_queue<state_t> q; // dijkstra from src
        q.push((state_t) { src, 0 });
        while (not q.empty()) {
            state_t s = q.top(); q.pop();
            if (sdist[s.i] != -1) continue;
            sdist[s.i] = s.cost;
            if (s.i == dst) break;
            for (edge_t e : g[s.i]) if (sdist[e.to] == -1) {
                if (s.cost + e.cost_to_terminal + dist[e.terminal] <= mid) { // NESUGOSHI
                    q.push((state_t) { e.to, s.cost + e.cost });
                }
            }
        }
        (sdist[dst] == -1 ? low : high) = mid;
    }
    cout << high << endl;
    return 0;
}
```
