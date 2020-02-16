---
layout: post
alias: "/blog/2017/04/30/arc-073-d/"
date: "2017-04-30T20:54:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "knapsack-problem" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc073/tasks/arc073_b" ]
---

# AtCoder Regular Contest 073: D - Simple Knapsack

たくさんバグを埋めた。

-   `int total = min<ll>(3*n, total_w - cnt*(ll)base);` とすべきところを `int total = total_w - cnt*(ll)base;` としてMLE/RE
-   `if (total < 0) break;` とすべきところを `if (total <= 0) break;` としてWA

## solution

使用する物の個数$k \le n$を固定すると許容できる重さの$w\_1$からの増分の総和$W - kw\_1$が定まる。
$w\_i' = w\_i - w\_1$として重さの多項式のknapsack問題を解けばよい。$O(N^4)$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
constexpr ll inf = ll(1e18)+9;
int main() {
    int n, total_w; scanf("%d%d", &n, &total_w);
    vector<int> w(n), v(n); repeat (i,n) scanf("%d%d", &w[i], &v[i]);
    int base = w[0];
    vector<int> delta(n);
    repeat (i,n) {
        delta[i] = w[i] - base;
        assert (0 <= delta[i] and delta[i] <= 3);
    }
    ll result = 0;
    for (int cnt = total_w / (base + 3); cnt <= n; ++ cnt) {
        int total = min<ll>(3*n, total_w - cnt*(ll)base);
        if (total < 0) break;
        auto dp = vectors<ll>(cnt+1, total+1, - inf);
        dp[0][0] = 0;
        repeat (i,n) {
            repeat_reverse (j,cnt) {
                repeat_reverse (k,total+1) if (k+delta[i] <= total) {
                    setmax(dp[j+1][k+delta[i]], dp[j][k] + v[i]);
                }
            }
        }
        repeat (k,total+1) {
            setmax(result, dp[cnt][k]);
        }
    }
    printf("%lld\n", result);
    return 0;
}
```
