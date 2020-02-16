---
layout: post
alias: "/blog/2016/02/23/abc-032-d/"
date: 2016-02-23T01:29:36+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "knapsack-problem", "dp", "typical-problem", "branch-and-bound" ]
---

# AtCoder Beginner Contest 032 D - ナップサック問題

0/1-knapsack問題を種々の制約の下での解く教科書的な問題。

なのだけど、分枝限定法を使えば全制約に対応できてしまう。しかも速度も上。制約を適当に弄って雑に比較したが、試した限り全て動的計画法より上だった。
計算量どうなってるのだろう。

## [D - ナップサック問題](https://beta.atcoder.jp/contests/abc032/tasks/abc032_d)

### 解法

-   枝刈り全探索 $O(2^N)$
    -   頑張る
        -   半分全列挙
        -   [editorial](http://www.slideshare.net/chokudai/abc032)
-   動的計画法 $O(NW)$
    -   $O(NW)$
        -   $O(N \Sigma w_i)$
    -   $O(N \Sigma v_i)$
-   分枝限定法
    -   なんかすごく速い やばい

### 実装

`if (n <= 30) { ... }`を`if (true) { ... }`にすると高速化する。
$N$が大きい場合は線形緩和問題を解く貪欲を累積和と二分探索でやるほうがよさそう。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
template <typename T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <typename T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
int main() {
    int n; ll lim_w; cin >> n >> lim_w;
    vector<ll> v(n), w(n); repeat (i,n) cin >> v[i] >> w[i];
    ll max_v = *max_element(v.begin(), v.end());
    ll max_w = *max_element(w.begin(), w.end());
    ll sum_w = accumulate(w.begin(), w.end(), 0ll);
    ll sum_v = accumulate(v.begin(), v.end(), 0ll);
    ll ans = 0;
    if (sum_w <= lim_w) {
        ans = sum_v;
    } else if (n <= 30) { // branch and bound
        /* sort by the efficiency */ {
            vector<int> xs(n); repeat (i,n) xs[i] = i;
            sort(xs.begin(), xs.end(), [&](int i, int j) -> bool { return v[i] * w[j] > v[j] * w[i]; });
            vector<ll> tv = v, tw = w;
            repeat (i,n) { v[i] = tv[xs[i]]; w[i] = tw[xs[i]]; }
        }
        function<void (int, ll, ll)> f = [&](int i, ll cur_v, ll cur_w) {
            if (lim_w < cur_w) return; // not executable
            if (i == n) { setmax(ans, cur_v); return; } // terminate
            ll lr_v = cur_v; // linear relaxation
            ll lr_w = cur_w;
            int j;
            for (j = i; j < n and lr_w + w[j] <= lim_w; ++ j) { // greedy
                lr_w += w[j];
                lr_v += v[j];
            }
            if (lr_w == lim_w or j == n) { setmax(ans, lr_v); return; } // accept greedy
            double lr_ans = lr_v + v[j] * ((lim_w - lr_w) /(double) w[j]);
            if (lr_ans <= ans) return; // bound
            f(i+1, cur_v+v[i], cur_w+w[i]);
            f(i+1, cur_v,      cur_w     );
        };
        f(0, 0, 0);
    } else if (max_w <= 1000) { // dynamic programming
        vector<ll> dp(lim_w+1);
        repeat (i,n) {
            repeat_reverse (j, lim_w-w[i]+1) {
                setmax(dp[j + w[i]], dp[j] + v[i]);
            }
        }
        repeat (j, lim_w+1) {
            setmax(ans, dp[j]);
        }
    } else if (max_v <= 1000) { // dynamic programming
        vector<ll> dp(sum_v+1, lim_w+1);
        dp[0] = 0;
        repeat (i,n) {
            repeat_reverse (j, sum_v-v[i]+1) {
                setmin(dp[j + v[i]], dp[j] + w[i]);
            }
        }
        repeat_reverse (j, sum_v+1) {
            if (dp[j] <= lim_w) {
                ans = j;
                break;
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```
