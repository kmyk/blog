---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-060-e/
  - /blog/2018/01/04/arc-060-e/
date: "2018-01-04T11:55:19+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "doubling", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc060/tasks/arc060_c" ]
---

# AtCoder Regular Contest 060: E - 高橋君とホテル / Tak and Hotels

見れば分かった。[東京大学プログラミングコンテスト2012: H - 区間スケジューリングクエリ](https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_08)を直前に解いていたため。

## solution

doubling。前処理$O(N \log N)$ クエリ$O(Q \log N)$。

愚直解としては、進めるところまで貪欲に進むことを繰り返せばよい。
このときあるホテルを出発して次に泊まるホテルは一意に定まる。
これを事前に求めておきdoublingを用いればクエリあたり$O(\log N)$となる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch_max(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    ++ r;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? l : r) = m;
    }
    return l;
}

struct doubling_table {
    vector<vector<int> > table;
    doubling_table() = default;
    doubling_table(vector<int> const & next, int size = -1) {
        int n = next.size();
        {
            auto it = minmax_element(ALL(next));
            assert (0 <= *(it.first) and *(it.second) <= n);
        }
        if (size == -1) {
            size = max<int>(1, ceil(log2(n)));
        }
        table.resize(size);
        table[0] = next;
        REP (k, size - 1) {
            table[k + 1].resize(n, n);
            REP (i, n) if (table[k][i] != n) {
                table[k + 1][i] = table[k][table[k][i]];
            }
        }
    }
};

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);
    int l; scanf("%d", &l);
    // prepare
    vector<int> next(n);
    REP (i, n) {
        next[i] = binsearch_max(i, n - 1, [&](int j) {
            return a[j] - a[i] <= l;
        });
    }
    doubling_table doubling(next);
    // serve
    int queries; scanf("%d", &queries);
    while (queries --) {
        int a, b; scanf("%d%d", &a, &b);
        -- a; -- b;
        if (a > b) swap(a, b);
        int result = 0;
        REP_R (k, doubling.table.size()) {
            if (doubling.table[k][a] < b) {
                a = doubling.table[k][a];
                result += 1 << k;
            }
        }
        while (a < b) {
            a = next[a];
            result += 1;
        }
        // output
        printf("%d\n", result);
    }
    return 0;
}
```
