---
layout: post
alias: "/blog/2015/11/04/arc-016-c/"
title: "AtCoder Regular Contest 016 C - ソーシャルゲーム"
date: 2015-11-04T22:24:05+09:00
tags: [ "competitive", "writeup", "arc", "atcoder", "probability", "dp", "bit-dp" ]
---

AtCoder Regular ContestのC問題、全完しました。

問題としてはそう難しくはないのだろうとは思う。
しかし私の場合は解説を見てもなおかなり苦戦した。

<!-- more -->

## [C - ソーシャルゲーム](https://beta.atcoder.jp/contests/arc016/tasks/arc016_3)

### 問題

お金を払ってくじを引ける。くじを引くとアイドルがひとり手に入る。くじは複数種類ある。
くじ毎に金額とアイドルの出現確率が与えられるので、最適な戦略を取ったときの、全アイドルの入手に必要な金額の期待値を求めよ。

### 解法

後ろからbit-dp。`dp[入手済みアイドルの集合] = コンプリートまでに必要な金額の期待値`。$O(m2^n)$。


前からやろうとすると、そもそも期待値にならないのでだめ。

久しぶりに期待値なんて概念を使ったので少し混乱したので、その部分だけメモしておく。
くじ$i$を引いたとき、確率$q$で入手済みのアイドルを入手できるとすると、
未入手のアイドルを引くまでにくじを引く回数の期待値は、
$$ \sum_{n = 1}^{\infty} q^{n-1}n = \frac{1}{1-q} \cdot \sum_{n = 1}^{\infty} q^n = \frac{1}{(1 - q)^2} $$となる。
これ以降の詳しい式はまあ適当にやればでてくる。


### 実装

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= (m); --(i))
#define repeat_reverse(i,n) repeat_from_reverse(i,0,n)
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<int> c(m);
    vector<int> cost(m);
    vector<vector<int> > idol(m);
    vector<vector<int> > p(m);
    repeat (i,m) {
        cin >> c[i] >> cost[i];
        idol[i].resize(c[i]);
        p[i].resize(c[i]);
        repeat (j,c[i]) {
            cin >> idol[i][j] >> p[i][j];
            -- idol[i][j];
        }
    }
    vector<double> dp(1 << n, INFINITY);
    dp[(1 << n) - 1] = 0;
    repeat_reverse (s, 1 << n) {
        repeat (i, m) {
            double acc = 0;
            int q = 0; // duplicated
            repeat (j, c[i]) {
                int t = s | (1 << idol[i][j]);
                if (s == t) q += p[i][j];
            }
            if (q == 100) continue;
            repeat (j, c[i]) {
                int t = s | (1 << idol[i][j]);
                if (s != t) acc += cost[i] * (p[i][j]/100.0 / pow(1 - q/100.0, 2))
                                    + (p[i][j]/100.0 / (1 - q/100.0)) * dp[t];
            }
            dp[s] = min(dp[s], acc);
        }
    }
    printf("%.12lf\n", dp[0]);
    return 0;
}
```
