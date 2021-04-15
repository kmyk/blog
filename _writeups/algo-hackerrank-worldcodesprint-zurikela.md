---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/worldcodesprint-zurikela/
  - /blog/2016/01/31/hackerrank-worldcodesprint-zurikela/
date: 2016-01-31T01:43:49+09:00
tags: [ "competitive", "writeup", "hackerrank", "independent-set", "maximum-independent-set", "graph", "world-codesprint" ]
---

# HackerRank World Codesprint: Zurikela's Graph

## [Zurikela's Graph](https://www.hackerrank.com/contests/worldcodesprint/challenges/zurikela)

### 問題

グラフに対し以下のクエリを処理し、最大独立集合問題の大きさを求めよ。

-   `A`: $x$個の頂点を加える。これらを新しいグループとする。
-   `B`: グループ$x,y$に含まれる頂点$u \in x, v \in y$の間に$\|x\|\dot\|y\|$個の辺$u - v$を張る。
-   `C`: グループ$x$の頂点と連結な頂点を全て集め、これらからなる新しいグループを作る。古いグループは消去される。

独立集合とは頂点の部分集合で、その任意の2頂点間に辺がないものである。

### 解説

やればできる。

グループを頂点とするグラフで考える。
頂点は重みとして、そのグループに含まれる元のグラフの頂点の数を持つ。

`C`のクエリに関して、指定されたグループの頂点から連結な頂点の集合からなるグラフの最大独立集合の大きさを$y$として、$y$個の頂点からなるグループを追加することと等しい。
グループ内の頂点の間に辺が張られることはないからである。

最大独立集合に関して、これは再帰的に計算すれば求まる。
頂点を使用したとき、その頂点に隣接する頂点にも使用済みの印を付けるようにする。
[指数時間アルゴリズム入門](http://www.slideshare.net/wata_orz/ss-12131479)を参考にした。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll independent(int x, vector<bool> const & available, vector<ll> const & nodes, vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> xs;
    map<int,int> connected; {
        function<void (int)> dfs = [&](int x) {
            connected[x] = xs.size();
            xs.push_back(x);
            for (int y : g[x]) if (available[y] and not connected.count(y)) dfs(y);
        };
        dfs(x);
    }
    vector<bool> used(n);
    function<ll (int)> dfs = [&](int i) -> ll {
        if (i == xs.size()) return 0;
        ll a = dfs(i+1); // don't use `i'
        ll b = 0; // use `i'
        if (not used[i]) {
            // push
            used[i] = true;
            vector<int> removed;
            for (int y : g[xs[i]]) if (connected.count(y)) {
                int j = connected[y];
                if (not used[j]) {
                    used[j] = true;
                    removed.push_back(j);
                }
            }
            // call
            b = dfs(i+1) + nodes[xs[i]];
            // pop
            used[i] = false;
            for (int j : removed) used[j] = false;
        }
        return max(a,b);
    };
    return dfs(0);
}
int main() {
    vector<bool> available;
    vector<ll> nodes;
    vector<vector<int> > g;
    function<void (int)> erase = [&](int x) {
        available[x] = false;
        for (int y : g[x]) if (available[y]) erase(y);
    };
    int q; cin >> q;
    repeat (qi,q) {
        char type; cin >> type;
        if (type == 'A') {
            int x; cin >> x;
            available.push_back(true);
            nodes.push_back(x);
            g.emplace_back();
        } else if (type == 'B') {
            int x, y; cin >> x >> y; -- x; -- y;
            g[x].push_back(y);
            g[y].push_back(x);
        } else if (type == 'C') {
            int x; cin >> x; -- x;
            available.push_back(true);
            nodes.push_back(independent(x, available, nodes, g));
            g.emplace_back();
            erase(x);
        }
    }
    ll ans = 0;
    repeat (x,g.size()) if (available[x]) {
        ans += independent(x, available, nodes, g);
        erase(x);
    }
    cout << ans << endl;
    return 0;
}
```
