---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-699-med/
  - /blog/2017/03/24/srm-699-med/
date: "2017-03-24T13:13:30+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "bfs" ]
"target_url": [ "https://community.topcoder.com/stat?c=problem_statement&pm=14387" ]
---

# TopCoder SRM 699 Div1 Medium: FromToDivisible

## problem

整数対の列$(a_1, b_1), (a_2, b_2), \dots, (a_m, b_m)$で説明される$N$頂点の有向グラフ$G$がある。
頂点は$1$から$N$までの番号が降られており、$\exists i. a_i \mid u \land b_i \mid v$であることと有向辺$u \to v$の存在が同値となっている。
$s \to t$最短路の長さを答えよ。

## solution

クエリを頂点として$m+2$頂点の有向グラフを作る。$O(M^2)$

$s,t$とクエリ$(a_i, b_i)$に対応する頂点を用意する。
$N$頂点のグラフの上でクエリ$i$による辺の次にクエリ$j$による辺を使える(つまり$\mathrm{lcm}(b_i, a_j) \le n$)とき$m+2$頂点のグラフの上で辺$i \to j$を張るようにする。
$s, t$は適当にして、求めた距離から$1$引いたのが答え。

$\hat{3}= \\{ 3k \le n \mid k \in \mathbb{N} \\}$のような整数の集合を頂点としてもできそうだが、面倒になりそう。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class FromToDivisible { public: int shortest(int n, int s, int t, vector<int> const & a, vector<int> const & b); };

ll gcd(ll a, ll b) { while (a) { b %= a; swap(a, b); } return b; }
ll lcm(ll a, ll b) { return (a * b) / gcd(a,b); }
constexpr int inf = 1e9+7;
int FromToDivisible::shortest(int n, int s, int t, vector<int> const & a, vector<int> const & b) {
    int m = a.size();
    // construct graph
    vector<vector<int> > g(m + 2);
    const int src = m;
    const int dst = m+1;
    repeat (p,m) {
        repeat (q,m) {
            if (lcm(b[p], a[q]) <= n) {
                g[p].push_back(q);
            }
        }
        if (s % a[p] == 0) g[src].push_back(p);
        if (t % b[p] == 0) g[p].push_back(dst);
    }
    // bfs
    vector<int> dist(g.size(), inf);
    queue<int> que;
    dist[src] = 0;
    que.push(src);
    while (not que.empty()) {
        int i = que.front(); que.pop();
        for (int j : g[i]) {
            if (dist[i] + 1 < dist[j]) {
                dist[j] = dist[i] + 1;
                que.push(j);
            }
        }
    }
    return dist[dst] < inf ? dist[dst]-1 : -1;
}
```
