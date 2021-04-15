---
layout: post
date: 2018-08-29T03:18:39+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "median", "bianry-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc101/tasks/arc101_b" ]
redirect_from:
  - /writeup/algo/atcoder/arc_101_d/
  - /writeup/algo/atcoder/arc-101-d/
---

# AtCoder Regular Contest 101: D - Median of Medians

## 解法

二分探索して中央値でなく多数決の問題にする。
$O(N \log \max a_i)$。

分からないときはまず簡単な場合で考えてみるのは典型。
$$1 \le a_i \le 10^9$$ でなくて $$a_i \in \{ 0, 1 \}$$ ならどうだろうか。
これは上手くやれば解ける。
$$r$$ をずらしながら区間 $$[0, r), [1, r), \dots, [r - 1, r)$$ 中の $$0$$ の数と $$1$$ の数の差を管理してやればよい。
$$r$$ を右にずらしたときはそれまでの値がすべて $$1$$ ずれるだけなのでいい感じにできる。
答えの値を二分探索することで $$a_i \in \{ 0, 1 \}$$ の場合に帰着できるのでこれだけ解けばよいことも分かる。
二分探索して2値に落とすのは典型。
これで解けた。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;
        (p(m) ? r : l) = m;
    }
    return r;
}

bool solve01(int n, vector<bool> const & a) {
    ll cnt[2] = {};
    map<int, int> acc;
    int base = 0;
    int pos = 0, neg = 0;
    for (int a_i : a) {
        assert (a_i == 0 or a_i == 1);
        if (a_i) {
            neg -= acc[base - 1];
            pos += acc[base - 1];
            base -= 1;
            acc[base + 1] += 1;
            pos += 1;
        } else {
            pos -= acc[base];
            neg += acc[base];
            base += 1;
            acc[base - 1] += 1;
            neg += 1;
        }
        cnt[0] += neg;
        cnt[1] += pos;
    }
    return cnt[1] >= cnt[0];
}

int solve(int n, vector<int> const & a) {
    return binsearch(0, 1e9 + 7, [&](int m) {
        vector<bool> b(n);
        REP (i, n) b[i] = (a[i] > m);
        return not solve01(n, b);
    });
}

int main() {
    int n; cin >> n;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, a) << endl;
    return 0;
}
```
