---
layout: post
redirect_from:
  - /blog/2015/10/24/kupc-2015-c/
date: 2015-10-24T23:55:24+09:00
tags: [ "kupc", "competitive", "writeup", "graph", "warshall-floyd" ]
---

# 京都大学プログラミングコンテスト2015 C - 最短経路

そういえばbellman-ford法が記憶から消えつつあるし復習しないと

となりの席だった人が、解法は分かってたのにバグでAC逃してた。すごく惜しい。

<!-- more -->

## [C - 最短経路](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_c) {#c}

### 問題

>   ある単純有向グラフにおける任意の二頂点間の最短距離に関する条件が与えられる. その条件を満たす有向グラフが存在するかどうか判定せよ.

### 解法

与えられた条件をそのまま辺として張った単純有効グラフを考える。
直接ではなく他の点を迂回して移動した方が近いような点の組が存在するかどうかを考えればよい。
これはwarshall-floyd法を回して比較する、あるいは任意の3点に三角不等式のようなものが成り立っていること確認すればよい。

### 実装

入力の$-1$(辺が存在しないことを示す)は、適当な十分大きな値に置き換えておく良い。
更新の際に$-1$であるか一々判定せずとも`min`で上手く処理されるので、短くなるしバグが出にくくなる。

``` c++
#include <iostream>
#include <vector>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int main() {
    int datasets; cin >> datasets;
    repeat (dataset, datasets) {
        int n; cin >> n;
        vector<vector<ll> > e(n, vector<ll>(n));
        repeat (i,n) {
            repeat (j,n) {
                cin >> e[i][j];
                if (e[i][j] == -1) e[i][j] = 1000000007;
            }
        }
        vector<vector<ll> > g = e;
        repeat (i,n) g[i][i] = 0;
        repeat (k,n) {
            repeat (i,n) {
                repeat (j,n) {
                    g[i][j] = min(g[i][j], g[i][k] + g[k][j]);
                }
            }
        }
        cout << (g == e ? "YES" : "NO") << endl;
    }
    return 0;
}
```
