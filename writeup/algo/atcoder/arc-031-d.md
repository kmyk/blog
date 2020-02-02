---
layout: post
alias: "/blog/2016/01/16/arc-031-d/"
title: "AtCoder Regular Contest 031 D - 買い物上手"
date: 2016-01-16T19:31:37+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "flow", "maximum-flow", "dinic", "binary-search", "graphviz" ]
---

フローだと聞いていても自力で思い付くのはつらいフロー。

## [D - 買い物上手](https://beta.atcoder.jp/contests/arc031/tasks/arc031_4) {#d}

[解説](http://www.slideshare.net/chokudai/arc031)曰く、

>   「平均」を最大化/最小化 $\to$ 答えについて二分法

だそうな。

### 解法

二分探索 + 最大流。

求めるのは$x(X,Y) = \Sigma\_{i \in X} S_i / \Sigma\_{j \in Y} T_j$の最大値$x_m$。
逆にそのような$x_m$に関して、$\Sigma\_{i \in X} S_i / \Sigma\_{j \in Y} T_j \le x_m$が成り立つ。
つまり$\phi(x) \Leftrightarrow \forall (X,Y) \in F, \Sigma\_{i \in X} S_i \le x \Sigma\_{j \in Y} T_j$とすると$x_m = {\rm min} \\{ x \mid \phi(x) \\}$なので、この述語$\phi$の判定ができれば$x_m$は二分探索できる。

そこで、以下のようなフローネットワークの最大流$f(x)$を求める。すると$\phi(x) \Leftrightarrow \Sigma S_i \le f(x)$と書ける。
これを計算すればよい。

$X_i \to Y_j$の辺の張り方は、経験値$X_i$を貰うにはアイテム$Y_j$が必要であるとき、容量$\infty$の辺を張る。
図は入出力例の1番目に同じ。

[![](/blog/2016/01/16/arc-031-d/a.png)](/blog/2016/01/16/arc-031-d/a.dot)

これが上手く行く理由を納得するには、例えば下の様なグラフを作る入力(値段$100$のアイテム`1`を買えば経験値が$1$貰え、値段$1$のアイテム`2`を買えば経験値が$10$貰える)を考えればよい。
明らかに最大効率$x_m = 10$である。
ここで重要なのは流量が実数値であることがある。
ここで$x = x_m$としたときのフローを考えれば、$s$からの容量は全て使い切られており、$x_m$から減らせばそうでなくなることが分かる。

[![](/blog/2016/01/16/arc-031-d/b.png)](/blog/2016/01/16/arc-031-d/b.dot)

このグラフを流れるものは経験値である。
右側の$xT_i$の制約が表すのは、値段$T_i$の経験値変換効率$x$倍である。

"target_url": [ "small" ]
--- 自分でもあまり理解できていないので、説明できるのはここまで。 </small>

### 実装

`maximum_flow()`は[AtCoder Regular Contest 013 D](http://kimiyuki.net/blog/2016/01/16/arc-013-d/)のものを`s/\<ll\>/double/g`したもの。

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#include <queue>
#include <functional>
#include <limits>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
double maximum_flow(int s, int t, vector<vector<double> > const & capacity /* adjacency matrix */) { // dinic, O(V^2E)
    int n = capacity.size();
    vector<vector<double> > flow(n, vector<double>(n));
    auto residue = [&](int i, int j) { return capacity[i][j] - flow[i][j]; };
    vector<vector<int> > g(n); repeat (i,n) repeat (j,n) if (capacity[i][j] or capacity[j][i]) g[i].push_back(j); // adjacency list
    double result = 0;
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
        function<double (int, double)> augmenting_path = [&](int i, double cur) -> double {
            if (i == t or cur == 0) return cur;
            if (finished[i]) return 0;
            finished[i] = true;
            for (int j : g[i]) if (level[i] < level[j]) {
                double f = augmenting_path(j, min(cur, residue(i,j)));
                if (f > 0) {
                    flow[i][j] += f;
                    flow[j][i] -= f;
                    finished[i] = false;
                    return f;
                }
            }
            return 0;
        };
        bool cont = false;
        while (true) {
            double f = augmenting_path(s, numeric_limits<double>::max());
            if (f == 0) break;
            result += f;
            cont = true;
        }
        if (not cont) break;
    }
    return result;
}
const double EPS = 1e-6;
int main() {
    int n, m; cin >> n >> m;
    vector<vector<double> > g(n+m+2, vector<double>(n+m+2));
    int s = n+m, t = n+m+1;
    repeat (i,n) cin >> g[s][i];
    repeat (i,m) cin >> g[n+i][t];
    repeat (i,n) {
        int k; cin >> k;
        repeat (j,k) {
            int a; cin >> a;
            g[i][n+a-1] = INFINITY;
        }
    }
    double sum_s = 0; repeat (i,n) sum_s += g[s][i];
    double low = 0, high = sum_s;
    while (abs(high - low) > EPS) {
        double mid = (low + high) / 2;
        vector<vector<double> > h = g;
        repeat (i,m) h[n+i][t] *= mid;
        double f = maximum_flow(s,t,h);
        (f < sum_s ? low : high) = mid;
    }
    printf("%.12lf\n", low);
    return 0;
}
```
