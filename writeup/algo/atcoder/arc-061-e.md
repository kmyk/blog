---
layout: post
redirect_from:
  - /blog/2016/09/14/arc-061-e/
date: "2016-09-14T17:30:42+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "bfs" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc061/tasks/arc061_c" ]
---

# AtCoder Regular Contest 061 E - すぬけ君の地下鉄旅行 / Snuke's Subway Trip

star graphにやられてTLEが生えた。

## solution

辺の重みを$1$だけにして、幅優先探索で可能。
ただし単一の路線で繋がっている駅同士は、重み$1$の辺で直接繋がるようにまとめて追加する。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <queue>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    // input
    int n, m; cin >> n >> m;
    vector<unordered_map<int,vector<int> > > g(n);
    repeat (i,m) {
        int p, q, c; cin >> p >> q >> c; -- p; -- q;
        g[p][c].push_back(q);
        g[q][c].push_back(p);
    }
    // compute
    vector<int> dist(n, -1);
    queue<int> que;
    dist[0] = 0;
    que.push(0);
    vector<unordered_set<int> > used(n);
    function<void (int, int, int)> dfs = [&](int i, int c, int d) {
        used[i].insert(c);
        if (dist[i] == -1) {
            dist[i] = d;
            que.push(i);
        }
        for (int j : g[i][c]) {
            if (used[j].count(c)) continue;
            if (dist[j] != -1 and dist[j] < d) continue;
            dfs(j, c, d);
        }
    };
    while (not que.empty()) {
        int i = que.front(); que.pop();
        for (auto it : g[i]) {
            int c = it.first;
            if (not used[i].count(c)) {
                dfs(i, c, dist[i]+1);
            }
        }
    }
    // output
    cout << dist[n-1] << endl;
    return 0;
}
```
