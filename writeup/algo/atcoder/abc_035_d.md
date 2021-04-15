---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_035_d/
  - /writeup/algo/atcoder/abc-035-d/
  - /blog/2016/03/30/abc-035-d/
date: 2016-03-30T03:20:57+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "graph", "boost", "bgl", "dijkstra" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc035/tasks/abc035_d" ]
---

# AtCoder Beginner Contest 035 D - トレジャーハント

atcoderにboostが入った。なのでboost graph libraryを使ってみた。

library呼び出しゲーと化す問題が発生するから意図的に入れてないのだと思っていたが、そうではなかったらしい。
標準library縛りからの脱却は競技プログラミング界にとっても有益だと思う。良い。

また、pythonにもscipyやnumpyが追加されている。
[言語追加の際の動作確認用コンテスト](https://beta.atcoder.jp/contests/language-test-201603/)にある表から確認できる。
scipyにもdijkstra関数はある。

## 解法

単一始点最短経路。dijkstra。
張られる辺は有向で、戻ってくる必要があるので、辺を逆向きに進むような最短経路と併せて2回。

## 実装

bglは初めてだったので[notさんの提出](https://beta.atcoder.jp/contests/abc035/submissions/677414)を参考にした。
あの人なら試していそうだと見てみたらやはり試されていた。
問題が単純なこともあり、かなり$\alpha$同値な感じになっている。

``` c++
#include <iostream>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
using namespace boost;
using graph_t = adjacency_list<vecS, vecS, directedS, no_property, property<edge_weight_t, ll> >;
int main() {
    int n, m, t; cin >> n >> m >> t;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    graph_t g(n), g_rev(n);
    repeat (i,m) {
        int x, y, z; cin >> x >> y >> z; -- x; -- y;
        add_edge(x, y, z, g);
        add_edge(y, x, z, g_rev);
    }
    vector<ll> dist(n), dist_rev(n);
    vector<int> parent(n), parent_rev(n);
    dijkstra_shortest_paths(g,     0, distance_map(dist    .data()).predecessor_map(parent    .data()));
    dijkstra_shortest_paths(g_rev, 0, distance_map(dist_rev.data()).predecessor_map(parent_rev.data()));
    ll ans = 0;
    repeat (i,n) {
        if (i != 0 and (parent[i] == i or parent_rev[i] == i)) continue;
        setmax(ans, a[i] * (t - dist[i] - dist_rev[i]));
    }
    cout << ans << endl;
    return 0;
}
```
