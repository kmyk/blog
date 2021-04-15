---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_082_f/
  - /writeup/algo/atcoder/arc-082-f/
  - /blog/2017/09/04/arc-082-f/
date: "2017-09-04T15:19:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc082/tasks/arc082_d" ]
---

# AtCoder Regular Contest 082: F - Sandglass

バグか誤読がなければぎりぎり間に合っていたかと思われます。(rating $-38$)

## clar

-   Q. サンプルは正しいですか？ たとえばサンプル1のクエリ2では、ひっくり返す前にはBには砂がX入っているので答えはX-1 = 179に見えます。
-   A. 各クエリでは、時刻 $t\_i$ にパーツ A に入っている砂の量を答えてください（パーツ A が下になっていたとしてもです）。

## solution

$O(K + Q)$。

例えばサンプル1で$t = r\_1$より先では$0 \le a \le 60 = r\_1$の場合の答えは全て等しい。
$\min, \max$の操作により情報が潰れるため、開始時点での$a$を

-   $a = 0$と同一視できるもの ($0 \le a le l$)
-   $a = X$と同一視できるもの ($r \le a le X$)
-   それ以外 ($l \le a \le r$)

の$3$つに分類できる。
反転する各時刻$t = r\_j$での境界$l, r$と$a = 0, X$で始めたときの$a$の値を$O(K)$かけて事前計算しておけば、$a\_i$で始めたときの同じ$t$での値は$O(1)$で求まる。

## implementation

クエリは時系列順に与えられるのでしゃくとりっぽくすれば二分探索は不要。

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr int inf = 1e9+7;
int main() {
    int x, k; scanf("%d%d", &x, &k);
    vector<int> r(k); repeat (i, k) scanf("%d", &r[i]);
    if (r[0]) r.insert(r.begin(), 0);
    r.push_back(inf);
    vector<int> hi(k + 1, x);
    vector<int> ub(k + 1, x);
    vector<int> lb(k + 1);
    vector<int> lo(k + 1);
    repeat (i, k) {
        ll dt = r[i + 1] - r[i];
        if (i % 2 == 0) {
            hi[i + 1] = hi[i] - dt;
            ub[i + 1] = ub[i];
            lo[i + 1] = lo[i] - dt;
            lb[i + 1] = lb[i] + max<ll>(0, - lo[i + 1]);
        } else {
            hi[i + 1] = hi[i] + dt;
            lb[i + 1] = lb[i];
            lo[i + 1] = lo[i] + dt;
            ub[i + 1] = ub[i] - max(0, hi[i + 1] - x);
        }
        setmax(hi[i + 1], 0); setmin(hi[i + 1], x);
        setmax(ub[i + 1], 0); setmin(ub[i + 1], x);
        setmax(lb[i + 1], 0); setmin(lb[i + 1], x);
        setmax(lo[i + 1], 0); setmin(lo[i + 1], x);
    }
    int q; scanf("%d", &q);
    while (q --) {
        int t, a; scanf("%d%d", &t, &a);
        auto j = (upper_bound(whole(r), t) - r.begin()) - 1;
        if (a <= lb[j]) {
            a = lo[j];
        } else if (ub[j] <= a) {
            a = hi[j];
        } else {
            a = (a - lb[j]) + lo[j];
        }
        int dt = t - r[j];
        a = j & 1 ? min(x, a + dt) : max(0, a - dt);
        printf("%d\n", a);
    }
    return 0;
}
```
