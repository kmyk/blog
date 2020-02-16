---
layout: post
redirect_from:
  - /blog/2017/06/03/arc-075-e/
date: "2017-06-03T22:58:01+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "cumulative-sum", "optimization", "square-root-decomposition" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc075/tasks/arc075_c" ]
---

# AtCoder Regular Contest 075: E - Meaningful Mean

## solution

各点から$K$引いておけば総和が$\ge 0$を見ればよくなる。
平方分割 + 簡単な定数倍高速化。$O(N \sqrt{N} \log N)$。

問われているのは算術平均が$\frac{\sum\_{i \in [l, r)} a\_i}{r - l} \ge K$となるような区間$[l, r)$の数。
区間の長さによって制約の形が変わってしまうのは面倒。
しかし$b\_i = a\_i - K$としておけばこの条件は$\sum\_{i \in [l, r)} b\_i \ge 0$と等しい。

区間中の総和なので累積和を取ることを考える。$s\_r = \sum\_{i \lt r} b\_i$とする。
すると$\sum\_{i \in [l, r)} b\_i = s\_r - s\_l$なので条件は$s\_l \le s\_r$に書き換えられる。

そのようなものの数を数えよう。
左から順に見ていってそれまでの中で$s\_l \le s\_r$な$l$の数を数えたい。
`std::set`は要素が何番目か取得できないのでだめ。
値は最大で$10^{14}$以上になるのでbinary indexed treeなどでも難しい。
`std::vector`に毎回追加して整列し二分探索すると$O(N^2 \log N)$で間に合わない。
しかし$N$は$N \le 2 \times 10^5$と小さいので、平方分割し$O(N \sqrt{N} \log N)$なら間に合う。
$\sqrt{N}$回だけ整列し、未整列の長さが高々$\sqrt{N}$な列は愚直に数えればよい。

ただし定数倍が厳しいので以下のようにする必要がある。

1.  未整列の側をそれ単体で`std::sort`
2.  整列済の側と結合
3.  `std::inplace_merge`

先に結合してまとめて`std::sort`すると$10$倍ぐらい遅くなった。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

int main() {
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    vector<ll> d(n); repeat (i, n) d[i] = a[i] -(ll) k;
    vector<ll> acc(n+1); whole(partial_sum, d, acc.begin() + 1);
    ll result = 0;
    vector<ll> sorted, unsorted;
    int sqrt_n = sqrt(n) + 3;
    repeat (i, n+1) {
        result += whole(upper_bound, sorted, acc[i]) - sorted.begin();
        result += whole(count_if, unsorted, [&](ll x) { return x <= acc[i]; });
        unsorted.push_back(acc[i]);
        if (i % sqrt_n == 0) {
            whole(sort, unsorted);
            int size = sorted.size();
            sorted.insert(sorted.end(), unsorted.begin(), unsorted.end());
            inplace_merge(sorted.begin(), sorted.begin() + size, sorted.end());
            unsorted.clear();
        }
    }
    printf("%lld\n", result);
    return 0;
}
```
