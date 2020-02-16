---
layout: post
date: 2018-08-02T08:16:01+09:00
tags: [ "competitive", "writeup", "atcoder", "tkppc", "expected-value" ]
"target_url": [ "https://beta.atcoder.jp/contests/tkppc3/tasks/tkppc3_e" ]
---

# 技術室奥プログラミングコンテスト #3: E - デフレゲーム

## solution

期待値の線形性。$O(n)$。

ちょうど$k$面出して失敗する確率を$p(k)$、そのような時に得られる金額を$X(k)$とすると、答え$$\mathrm{ans} = \sum_i p(k) X(k)$$。
さらに$\le k$面出して失敗する確率$q(k)$を置けば$p(k) = q(k) - q(k - 1)$となり、これらは容易に求まる。

## implementation

実装が汚ないのは迷走の結果

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

int main() {
    int n; scanf("%d", &n);;

    vector<double> length_ge(n + 1);
    length_ge[0] = 1;
    REP (k, n) {
        length_ge[k + 1] = length_ge[k] * (n - k) / n;
    }

    double answer = 0;
    double e1 = (n + 1) / 2.0;
    REP (k, n + 1) {
        double length_eq = length_ge[k] * k / n;
        answer += length_eq * e1 * k;
    }

    printf("%.14lf\n", answer);
    return 0;
}
```
