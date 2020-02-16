---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-017-d/
  - /blog/2017/07/31/agc-017-d/
date: "2017-07-31T09:52:19+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "grundy-number", "game", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc017/tasks/agc017_d" ]
---

# AtCoder Grand Contest 017: D - Game on Tree

## solution

木DPでgrundy数を求める。$O(N)$。

grundy数の計算方法を再帰的に示す。
木$T$の根から$k$本の枝が出ていて、その頂点からの枝を含む部分木$T\_i$のgrundy数が$g\_i$ for $i \lt k$のとき、通常の公平ゲームの和であり木$T$全体では$g\_0 \oplus g\_1 \oplus \dots \oplus g\_{k-1}$。これは明らか。
ある木$T$でゲームをするときそのgrundy数が$g$であったとして、その根から$1$本生やしてその先を根と取り直して木$T'$とき、その木$T'$のgrundy数は$g^\star = g + 1$。
$T'$にするのに生やした辺を選択したとき、自明にgrundy数$0$な状態へ遷移する。
元々の木$T$ではgrundy数が$0, 1, \dots, g - 1$な状態に遷移できていて$g$には遷移できない。
根付き木としての部分木$S \subseteq T$に対し同様の$S'$を考えると、$T'$からは$0^\star, 1^\star, \dots, {g-1}^\star$に遷移できて$g^\star$には遷移できないことになる。帰納法の仮定が使えて、$T'$全体ではgrundy数$g + 1$であることが言える。

## implementation

``` c++
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    repeat (i, n - 1) {
        int x, y; scanf("%d%d", &x, &y); -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    vector<int> grundy(n);
    function<int (int, int)> go = [&](int i, int parent) {
        int acc = 0;
        for (int j : g[i]) if (j != parent) {
            acc ^= go(j, i) + 1;
        }
        return acc;
    };
    int result = go(0, -1);
    printf("%s\n", result ? "Alice" : "Bob");
    return 0;
}
```
