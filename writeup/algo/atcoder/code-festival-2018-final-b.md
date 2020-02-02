---
layout: post
title: "CODE FESTIVAL 2018 Final: B - Theme Color"
date: 2018-11-22T15:48:39+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "error", "overflow", "log" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2018-final/tasks/code_festival_2018_final_b" ]
---

## 解法

### 概要

自明を誤差などを抑えて計算してみよう系。
上手く精度を挙げれば解ける。
$$O(N + M)$$。

### 詳細

愚直に計算するのは $$R_i = N - \sum _ {j \lt i} r_j$$ とおいて $$M^{-N} \prod _ {i \le M} {} _ {R_i} C _ {r_i}$$ でよく、計算量的にも間に合う。
しかし何も考えず実装すると指数部のオーバーフローで途中で $$0$$ や $$\infty$$ になる。
例えば乱択ケースで試すと $$x \ge 10000$$ などになることが確認できるが、倍精度浮動小数点数で表現できる最小の正の数は $$2.2250738585072 \times 10^{-308}$$ なのでまったく足りない。
これは指数部を `int` を使ってemulateし、数値を $$(0.1, 10)$$ の範囲で計算してやることで解決される。
あるいは対数を取って計算することでも解決できる。

## メモ

何も理解せず通した

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

int solve(int n, int m, vector<int> const & r) {
    int x = 1;
    long double p = 1;
    for (int r_i : r) {
        REP (k, r_i) {
            p *= n - k;
            p /= k + 1;
            p /= m;
            while (p < 0.1) {
                p *= 10;
                x += 1;
            }
            while (p > 10) {
                p /= 10;
                x -= 1;
            }
        }
        n -= r_i;
    }
    return x;
}

int main() {
    int n, m; cin >> n >> m;
    vector<int> r(m);
    REP (i, m) cin >> r[i];
    cout << solve(n, m, r) << endl;
    return 0;
}
```
