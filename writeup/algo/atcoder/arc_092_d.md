---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-092-d/
  - /blog/2018/04/05/arc-092-d/
date: "2018-04-05T04:30:09+09:00"
tags: [ "competitive", "writeup", "arc", "xor", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc092/tasks/arc092_b" ]
---

# AtCoder Regular Contest 092: D - Two Sequences

## note

-   本番で解けず、解法読んで通してしてしばらくしてから見直しても解けず。何も成長していない
-   [editorial](https://img.atcoder.jp/arc092/editorial.pdf)の「xor の定義より，$N^2$ 個の $a\_i + b\_j$ のうち，k-bit 目が 1 のものが偶数個あるか奇数個あるか判定できれば良いです。」が思い付かない時点で終了。 「xorなので桁ごとに決める」は典型なんだけどこの問題はその雰囲気が薄いので出てこないっぽい
-   $O(N^2)$を普通にblockingしたら$3.5$secぐらいだった
-   SIMDに乗りやすいように内側のloopをいい感じunrollingすると$O(N^2)$も通るようだ
    -   例: <https://beta.atcoder.jp/contests/arc092/submissions/2242270>
    -   例: <https://beta.atcoder.jp/contests/arc092/submissions/2251371>
-   SIMDを落としたいために定数倍が厳しいので丁寧に実装する

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <iostream>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);
    vector<int> b(n); REP (i, n) scanf("%d", &b[i]);

    // solve
    int acc = 0;
    REP_R (k, 29) {
        sort(ALL(a));
        sort(ALL(b));
        int m = binsearch(0, n, [&](int j) {
            return b[j] >= (1 << k);
        });
        long long cnt = 0;
        for (int a_i : a) {
            bool pred = a_i & (1 << k);
            int l = binsearch(0, m, [&](int j) {
                return pred !=     bool((a_i + b[j]) & (1 << k));
            });
            int r = binsearch(m, n, [&](int j) {
                return pred != not bool((a_i + b[j]) & (1 << k));
            });
            cnt += pred ? n - (r - l) : r - l;
        }
        if (cnt % 2 == 1) {
            acc |= 1 << k;
        }
        REP (i, n) {
            a[i] &= ~ (1 << k);
            b[i] &= ~ (1 << k);
        }
    }

    // output
    printf("%d\n", acc);
    return 0;
}
```
