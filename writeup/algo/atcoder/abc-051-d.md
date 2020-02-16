---
layout: post
alias: "/blog/2017/01/07/abc-051-d/"
date: "2017-01-07T22:12:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "graph", "warshall-floyd" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc051/tasks/abc051_d" ]
---

# AtCoder Beginner Contest 051: D - Candidates of No Shortest Paths

ひさしぶりのABCだった。#041以来らしい。順位表も上位が日本人ばかりで懐しい感じだった。

unratedなので、一昨日から作っているsampleを取得したりするscriptの動作確認や修正もできてちょうどよかった。

## solution

Warshall Floyd法で全点対最短距離を出し、各辺に対してそれが使われているか見る。つまり重み$\mathrm{cost}$の辺$(i,k)$に対し$\exists j. d(i,j) = \mathrm{cost} + d(k,j)$を確認する。$O(N^3)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int main() {
    int n, m; cin >> n >> m;
    vector<vector<pair<int, int> > > g(n);
    repeat (i,m) {
        int a, b, c; cin >> a >> b >> c; -- a; -- b;
        g[a].emplace_back(b, c);
        g[b].emplace_back(a, c);
    }
    vector<vector<int> > dist = vectors(n, n, inf);
    repeat (i,n) dist[i][i] = 0;
    repeat (i,n) for (auto it : g[i]) dist[i][it.first] = it.second;
    repeat (k,n) repeat (i,n) repeat (j,n) setmin(dist[i][j], dist[i][k] + dist[k][j]); // warshall floyd
    int cnt = 0;
    repeat (i,n) for (auto it : g[i]) {
        int j, cost; tie(j, cost) = it;
        if (i > j) continue;
        bool used = false;
        repeat (k,n) {
            if (dist[i][k] == cost + dist[j][k]) {
                used = true;
                break;
            }
        }
        if (not used) cnt += 1;
    }
    cout << cnt << endl;
    return 0;
}
```
