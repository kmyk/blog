---
layout: post
date: 2018-12-07T01:52:27+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc097/tasks/arc097_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc-097-e/
---

# AtCoder Regular Contest 097: E - Sorted and Sorted

## 解法

### 概要

結果の列を固定すれば転倒数を計算するだけ。
結果の列を前から構成していってその過程を白黒のボールの使った数 $$(w, b)$$ で割ってDP。
列中の確定した部分の数字についての転倒数の和を持つ。
これをそのまま書くと $$O(N^3)$$ になる。
適当に前処理するなどすると $$O(N^2)$$ に落ちる。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;
template <class T, class U> inline void chmin(T & a, U const & b) { a = min<T>(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int solve(int n, vector<char> const & c, vector<int> const & a) {
    auto delta_w = vectors(n + 1, n + 1, int());
    REP (w, n + 1) {
        REP (i, 2 * n) {
            if (c[i] == 'B') {
                delta_w[w][0] += 1;
                delta_w[w][a[i] + 1] -= 1;
            } else {
                if (a[i] == w) break;
                delta_w[w][0] += (a[i] >= w);
            }
        }
        REP (b, n) {
            delta_w[w][b + 1] += delta_w[w][b];
        }
    }

    auto delta_b = vectors(n + 1, n + 1, int());
    REP (b, n + 1) {
        REP (i, 2 * n) {
            if (c[i] == 'B') {
                if (a[i] == b) break;
                delta_b[0][b] += (a[i] >= b);
            } else {
                delta_b[0][b] += 1;
                delta_b[a[i] + 1][b] -= 1;
            }
        }
        REP (w, n) {
            delta_b[w + 1][b] += delta_b[w][b];
        }
    }

    auto dp = vectors(n + 1, n + 1, INT_MAX);
    dp[0][0] = 0;
    REP (w, n + 1) {
        REP (b, n + 1) {
            if (w - 1 >= 0) {
                chmin(dp[w][b], dp[w - 1][b] + delta_w[w - 1][b]);
            }
            if (b - 1 >= 0) {
                chmin(dp[w][b], dp[w][b - 1] + delta_b[w][b - 1]);
            }
        }
    }
    return dp[n][n];
}

int main() {
    int n; cin >> n;
    vector<char> c(2 * n);
    vector<int> a(2 * n);
    REP (i, 2 * n) {
        cin >> c[i] >> a[i];
        -- a[i];
    }
    cout << solve(n, c, a) << endl;
    return 0;
}
```
