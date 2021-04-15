---
redirect_from:
  - /writeup/algo/atcoder/code-festival-2018-final-a/
layout: post
date: 2018-11-22T15:35:47+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2018-final/tasks/code_festival_2018_final_a" ]
---

# CODE FESTIVAL 2018 Final: A - 2540

## 解法

### 概要

中央を固定する。
和 $$A = 2540$$ を使って $$O((N + M) \log A)$$ あるいは $$O(N + M)$$。

### 詳細

組 $$(a, b, c)$$のうち中央 $$b$$ に注目する。
$$b$$ を固定して $$d(b, x) = y$$ な $$x$$ の数を $$f(y)$$ と書くとすると $$f(0) f(2540) + f(1) f(2539) + \dots + f(1269) f(1271) + f(1270) (f(1270) - 1)$$ を数えればよい。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

int main() {
    int n, m; cin >> n >> m;
    vector<map<int, int> > k(n);
    REP (j, m) {
        int a, b, l; cin >> a >> b >> l;
        -- a; -- b;
        k[a][l] += 1;
        k[b][l] += 1;
    }
    ll cnt = 0;
    REP (i, n) {
        REP (l, 2540 + 1) {
            if (k[i].count(l) and k[i].count(2540 - l)) {
                if (l != 2540 - l) {
                    cnt += (ll)k[i][l] * k[i][2540 - l];
                } else {
                    cnt += (ll)k[i][l] * (k[i][l] - 1);
                }
            }
        }
    }
    cnt /= 2;
    cout << cnt << endl;
    return 0;
}
```
