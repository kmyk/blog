---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-633-med/
  - /blog/2016/01/16/srm-633-med/
date: 2016-01-16T10:15:38+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "maximum-flow", "flow", "graph", "warshall-floyd", "edmonds-karp", "graphviz" ]
---

# TopCoder SRM 633 Div1 Medium: DoubleTree

kmjpさんの解説を見ながら解いた。

## [Medium: DoubleTree](https://community.topcoder.com/stat?c=problem_statement&pm=13359)

### 問題

長さ$n$($n \le 50$)の数列$a$が与えられる。負数を含む。
頂点数$n$の木$G$,$H$が与えられる。

集合$S \subset \{ 0, 1, \dots, n-1 \}$で、$G$,$H$から誘導されるsubgraph $G[S]$,$H[S]$が共に連結であるものに関し、$\Sigma\_{i \in S} a_i$の最大値を答えよ。

### 解説

最大流。

まず依存関係に関して。
木の頂点$i$,$j$間の唯一の道上に頂点$k$があることは、${\rm dist}\_{i,k} + {\rm dist}\_{k,j} = {\rm dist}\_{i,j}$で判定できる。三角不等式っぽい。
事前にwarshall-floydしておけばよい。

これを最大流で解く。
採用する頂点をひとつ固定して考える。
すると採用したときの依存関係がひとつの有向グラフに収まる。
これに頂点$s,t$を加え、最小cutがpenaltyとなるグラフを作る。
負のpenaltyつまり正の点数に対応するため、点数が正なら$s$側に負なら$t$側にその絶対値の重みの辺を張り、これを$\Sigma_j {\rm max}\{0, a_j\}$から引けばよい。必ず採用するとした辺の重みは適切にしておく。

一番最後のサンプルで頂点$1$を必ず採用するとしたときのグラフは以下のようになる。ただし、頂点や依存関係の辺は最低限のみ置き、容量$0$の辺は省略している。

[![](/blog/2016/01/16/srm-633-med/a.png)](/blog/2016/01/16/srm-633-med/a.dot)

参考として、入力となる木は以下で重みは$-3, 2, 2, -1, 2, 2, -1$。

[![](/blog/2016/01/16/srm-633-med/b.png)](/blog/2016/01/16/srm-633-med/b.dot)
[![](/blog/2016/01/16/srm-633-med/c.png)](/blog/2016/01/16/srm-633-med/c.dot)


### 実装

`maximum_flow()`は[Yukicoder No.119](http://kimiyuki.net/blog/2016/01/15/yuki-119/)のときのものからそのまま。

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class DoubleTree { public: int maximalScore(vector<int> a, vector<int> b, vector<int> c, vector<int> d, vector<int> score); };
ll maximum_flow(int s, int t, vector<vector<ll> > const & g /* capacity, adjacency matrix */) { // edmonds karp, O(E^2V)
    int n = g.size();
    vector<vector<ll> > flow(n, vector<ll>(n));
    auto residue = [&](int i, int j) { return g[i][j] - flow[i][j]; };
    ll result = 0;
    while (true) {
        vector<int> prev(n, -1);
        vector<ll> f(n);
        // find the shortest augmenting path
        queue<int> q; // bfs
        q.push(s);
        while (not q.empty()) {
            int i = q.front(); q.pop();
            repeat (j,n) if (prev[j] == -1 and j != s and residue(i,j) > 0) {
                prev[j] = i;
                f[j] = residue(i,j);
                if (i != s) f[j] = min(f[j], f[i]);
                q.push(j);
            }
        }
        if (prev[t] == -1) break; // not found
        // backtrack
        for (int i = t; prev[i] != -1; i = prev[i]) {
            int j = prev[i];
            flow[j][i] += f[t];
            flow[i][j] -= f[t];
        }
        result += f[t];
    }
    return result;
}
const ll INF = 1000000007;
int DoubleTree::maximalScore(vector<int> a, vector<int> b, vector<int> c, vector<int> d, vector<int> score) {
    int n = score.size();
    // warshall floyd
    vector<vector<ll> > g(n, vector<ll>(n, INF));
    vector<vector<ll> > h(n, vector<ll>(n, INF));
    repeat (i,n) {
        g[i][i] = 0;
        h[i][i] = 0;
    }
    repeat (i,n-1) {
        g[a[i]][b[i]] = 1;
        g[b[i]][a[i]] = 1;
        h[c[i]][d[i]] = 1;
        h[d[i]][c[i]] = 1;
    }
    repeat (k,n) repeat (i,n) repeat (j,n) {
        g[i][j] = min(g[i][j], g[i][k] + g[k][j]);
        h[i][j] = min(h[i][j], h[i][k] + h[k][j]);
    }
    // flow
    ll total = 0; for (int it : score) if (it > 0) total += it;
    ll penalty = total;
    repeat (i,n) {
        vector<vector<ll> > f(n+2, vector<ll>(n+2));
        int s = n, t = n+1;
        f[s][i] = INF;
        repeat (j,n) if (j != i) {
            if (score[j] >= 0) {
                f[s][j] = score[j];
            } else {
                f[j][t] = - score[j];
            }
        }
        repeat (j,n) if (j != i) {
            repeat (k,n) {
                if (g[i][k] + g[k][j] == g[i][j]) f[j][k] = INF;
                if (h[i][k] + h[k][j] == h[i][j]) f[j][k] = INF;
            }
        }
        penalty = min(penalty, maximum_flow(s, t, f) - min(0, score[i]));
    }
    return total - penalty;
}
```
