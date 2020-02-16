---
layout: post
alias: "/blog/2017/10/03/jag2017summer-day3-f/"
date: "2017-10-03T06:58:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag-summer", "graph", "bipartite-graph", "bfs" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2017summer-day3/tasks/jag2017summer_day3_f" ]
---

# Japan Alumni Group Summer Camp 2017 Day 3: F - Endless BFS

頂点への訪問情報をふたつ持つDFSでいけそうと言っていたら、後輩が(同じなのだが)二部グラフだと整理してくれた。
実装は彼に任せた。でも変なDijkstraライブラリ貼ってバグらせてた。

## problem

与えられたグラフ上で問題文中のBFSっぽいコードを実行して、停止するか、するとしたら何ステップ後か答えよ。

## solution

元の頂点をそれぞれ複製し辺は斜めに貼り替えて二部グラフを作る。
これが連結でなければ停止しない。
この上でBFSし、それぞれの色の中での距離の最大値を求め、そのふたつの中の最小値が答え。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <limits>
#include <queue>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

vector<int> breadth_first_search(int root, vector<vector<int> > const & g) {
    vector<int> dist(g.size(), numeric_limits<int>::max());
    queue<int> que;
    dist[root] = 0;
    que.push(root);
    while (not que.empty()) {
        int i = que.front();
        que.pop();
        for (int j : g[i]) if (dist[j] == numeric_limits<int>::max()) {
            dist[j] = dist[i] + 1;
            que.push(j);
        }
    }
    return dist;
}

int main() {
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<int> > g(2 * n);
    repeat (i, m) {
        int u, v; scanf("%d%d", &u, &v); -- u; -- v;
        g[u].push_back(v + n);
        g[v + n].push_back(u);
        g[v].push_back(u + n);
        g[u + n].push_back(v);
    }
    vector<int> dist = breadth_first_search(0, g);
    int a = *max_element(dist.begin(), dist.begin() + n);
    int b = *max_element(dist.begin() + n, dist.end());
    int result = min(a, b);
    if (result == numeric_limits<int>::max()) result = -1;
    printf("%d\n", result);
    return 0;
}
```
