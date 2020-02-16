---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-051-d/
  - /blog/2017/12/31/arc-051-d/
date: "2017-12-31T22:26:21+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "lie", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc051/tasks/arc051_d" ]
---

# AtCoder Regular Contest 051: D - 長方形

## solution

嘘解法。定数倍高速化。$O(HW)$を削る。

縦と横で独立に$[0, z)$の間にある長さ$l$の連続部分の総和の最大値を$\mathrm{dp}(z, l)$として求める。
クエリ$(A, B)$ごとに$\max \\{ l\_b \mathrm{dp}(A, l\_a) + l\_a \mathrm{dp}(B, l\_b) \mid 1 \le l\_a \le A, 1 \le l\_b \le B \\}$を求めればよいが、これでは$O(AB)$で少し遅い。
そこで各$A$について対$(l\_a, \mathrm{dp}(A, l\_a))$の中で結果に影響しそうなものだけ選んで他を(嘘ではあるが)捨てる。$B$についても同様。
それぞれ半分に落とせばおよそ$4$倍速。選び方を試行錯誤すれば通る。

## implementation

``` c++
#pragma GCC optimize("O3")
#pragma GCC target("avx")
#include <algorithm>
#include <cstdio>
#include <map>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

const ll inf = ll(1e18)+9;
vector<vector<int> > get_dp(int w, vector<int> const & a) {
    vector<int> acc(w + 1);
    repeat (x, w) acc[x + 1] += acc[x] + a[x];
    vector<vector<int> > dp(w + 1);
    repeat_from (x, 1, w + 1) {
        dp[x].resize(x + 1);
        repeat_from (z, 1, x) {
            dp[x][z] = max(dp[x - 1][z], acc[x] - acc[x - z]);
        }
        dp[x][x] = acc[x] - acc[0];
    }
    return dp;
}
vector<vector<pair<int, int> > > shrink_dp(int w, vector<vector<int> > const & dp) {
    vector<vector<pair<int, int> > > ndp(w + 1);
    repeat_from (x, 1, w + 1) {
        repeat_from (z, 1, x + 1) {
            ndp[x].emplace_back(z, dp[x][z]);
        }
        constexpr int l1 = 100;
        constexpr int l2 = 700;
        constexpr int l3 = 400;
        if (ndp[x].size() > l1 + l2 + l3) {
            partial_sort(ndp[x].begin(),           ndp[x].begin() + l1,           ndp[x].end(), [&](pair<int, int> a, pair<int, int> b) { return a.first < b.first; });
            partial_sort(ndp[x].begin() + l1,      ndp[x].begin() + l1 + l2,      ndp[x].end(), [&](pair<int, int> a, pair<int, int> b) { return a.first > b.first; });
            partial_sort(ndp[x].begin() + l1 + l2, ndp[x].begin() + l1 + l2 + l3, ndp[x].end(), [&](pair<int, int> a, pair<int, int> b) { return a.second > b.second; });
            ndp[x].resize(l1 + l2 + l3);
            ndp[x].shrink_to_fit();
        }
    }
    return ndp;
}
int main() {
    // input
    int w, h; scanf("%d%d", &w, &h);
    vector<int> a(w); repeat (x, w) scanf("%d", &a[x]);
    vector<int> b(h); repeat (y, h) scanf("%d", &b[y]);
    int q; scanf("%d", &q);
    vector<int> aq(q), bq(q); repeat (i, q) scanf("%d%d", &aq[i], &bq[i]);
    // solve
    auto dp_a = shrink_dp(w, get_dp(w, a));
    auto dp_b = shrink_dp(h, get_dp(h, b));
    map<pair<int, int>, ll> memo;
    repeat (i, q) {
        pair<int, int> key = { aq[i], bq[i] };
        if (not memo.count(key)) {
            ll result = - inf;
            for (auto p : dp_a[aq[i]]) {
                for (auto q : dp_b[bq[i]]) {
                    setmax(result, p.second *(ll) q.first + q.second *(ll) p.first);
                }
            }
            memo[key] = result;
        }
    }
    // output
    repeat (i, q) {
        pair<int, int> key = { aq[i], bq[i] };
        printf("%lld\n", memo[key]);
    }
    return 0;
}
```
