---
redirect_from:
layout: post
date: 2018-08-03T17:37:27+09:00
tags: [ "competitive", "writeup", "atcoder", "njpc", "dp", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/njpc2017/tasks/njpc2017_f" ]
---

# NJPC2017: F - ダブルス

## solution

DP。二分探索。答えの最大値$V$に対し最悪$O(N^2 \log V)$。十分速いがたぶん嘘。

まず愚直DPを考えよう。
合計$i$個打ち返してふたりの人がそれぞれ最後に打ち返したのは$l, r$番目であるような状態を作るまでに必要な速さの上限を $\mathrm{dp}(i, l, r) \in \mathbb{R}$ とするDP。
明らかに $i = l, r$ なので $l \lt r = i$ とすれば $\mathrm{dp}(l, r) \in \mathbb{R}$ に落とせる (典型)。
これは $O(N^2)$ なので部分点まで。

実家DPが典型だがどうやっても落とせない。
そこで答えを二分探索 (典型)。
速度を覚える必要がないので $\mathrm{dp}(l, r) \in 2$ とできて、 $r$のときの可能な$l$の集合 $\mathrm{dp}(r) \in 2^N$ を求めるDPに落とせる (典型)。
更新式の形を良く見て集合値関数に合わせて適切に実装し、何かを信じれば、定数倍が小さくなることとケースが弱いのか間に合ってしまう。

想定解では常に $\mathrm{dp}(i) = [l_i, r_i) \in 2^N$ となっているという事実 (典型) が使われていた。
移動に必要な速さを比較するのをやめて、ある位置に存在できるかという形で考えればこれが数直線上の区間を成すことから言える(はず)。

## note

-   「区間が連続になる」が本質っぽいのに二分探索部分で蹴躓いた上に嘘っぽい解法なのだめすぎる。実家だと決め付けてしまったのが失敗。
-   最悪ケースが自明に構成できたとしても、乱数生成ケースでは引っ掛らない場合、嘘が通るかどうかはテストケースの作り込み依存。意外とうっかり通ってしまう

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> t(n + 1), x(n + 1);
    REP (i, n) scanf("%d%d", &t[i + 1], &x[i + 1]);

    // solve
    auto cost = [&](int l, int r) { return (double)abs(x[r] - x[l]) / (t[r] - t[l]); };
    vector<int> dp;
    auto pred = [&](double v) {
        dp.clear();
        dp.push_back(0);
        REP (r, n) {
            bool found = false;
            for (int l : dp) {
                if (cost(l, r + 1) < v) {
                    found = true;
                    break;
                }
            }
            if (v < cost(r, r + 1)) dp.clear();
            if (found) dp.push_back(r);
            if (dp.empty()) return false;
        }
        return true;
    };
    double lo = 0, hi = 1e9;
    REP (iteration, 100) {
        double mi = (lo + hi) / 2;
        (pred(mi) ? hi : lo) = mi;
    }

    // output
    printf("%.10lf\n", hi);
    return 0;
}
```

愚直DP:

``` c++
    auto cost = [&](int l, int r) { return (double)abs(x[r] - x[l]) / (t[r] - t[l]); };
    auto dp = vectors(n + 1, n + 1, (double)INFINITY);
    dp[0][0] = 0;
    REP (r, n) {
        REP (l, r + 1) {
            chmin(dp[r + 1][r], max(dp[r][l], cost(l, r + 1)));
            chmin(dp[r + 1][l], max(dp[r][l], cost(r, r + 1)));
        }
    }
```
