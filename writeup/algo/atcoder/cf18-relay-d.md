---
layout: post
title: "Code Festival (2018) Team Relay: D - 数直線"
date: 2018-11-21T10:46:18+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "ternary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf18-relay-open/tasks/relay2018_d" ]
---

## 解法

### 概要

凸性により三分探索。$$O(N \log N)$$。

## メモ

整理すると「一次関数 $$f_0, f_1, \dots, f _ {2N - 1}$$ と区間 $$[l, r) \subseteq \mathbb{R}$$ が与えられるので $$\arg\min _ {x \in [l, r)} \max \{ f_i(x) \mid i \lt 2N \}$$ を求めよ」という問題になる。
凸性をもっと上手く使った賢い$$O(N)$$がありそうに思えるが二分探索しか思い付かなくて気持ち悪い。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T, class U> inline void chmax(T & a, U const & b) { a = max<T>(a, b); }

/**
 * @arg f must be a downward-convex function
 * @retrun argmin f
 * @note f is called (iteration + 1) times
 */
template <class Function>
double golden_section_search(double l, double r, int iteration, Function f) {
    static const double GOLDEN_RATIO = (1 + sqrt(5)) / 2;
    double m1 = l + (r - l) / (GOLDEN_RATIO + 1);
    double m2 = l + (r - l) / GOLDEN_RATIO;  // NOTE: this equals to GOLDEN_RATIO / (GOLDEN_RATIO + 1.0)
    double f1 = f(m1);
    double f2 = f(m2);
    while (iteration --) {
        if (f1 < f2){
            r = m2;
            m2 = m1;
            f2 = f1;
            m1 = l + (r - l) / (GOLDEN_RATIO + 1);
            f1 = f(m1);
        } else {
            l = m1;
            m1 = m2;
            f1 = f2;
            m2 = l + (r - l) / GOLDEN_RATIO;
            f2 = f(m2);
        }
    }
    return (l + r) / 2;
}

double solve(int n, vector<int> const & x, vector<int> const & w) {
    double l = *min_element(ALL(x));
    double r = *max_element(ALL(x));
    return golden_section_search(l, r, 100, [&](double p) {
        double acc = - INFINITY;
        REP (i, n) chmax(acc, abs(x[i] - p) * w[i]);
        return acc;
    });
}

int main() {
    int n; cin >> n;
    vector<int> x(n), w(n);
    REP (i, n) cin >> x[i] >> w[i];
    cout << setprecision(16) << solve(n, x, w) << endl;
    return 0;
}
```
