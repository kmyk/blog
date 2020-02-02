---
layout: post
alias: "/blog/2016/01/19/tdpc-h/"
title: "Typical DP Contest H - ナップザック"
date: 2016-01-19T22:48:58+09:00
tags: [ "competitive", "writeup", "atcoder", "typical-dp-contest", "dp" ]
---

dpだけど自力で解けました。

## [H - ナップザック](https://beta.atcoder.jp/contests/tdpc/tasks/tdpc_knapsack)

### 解法

DP。$O(NWC)$。

knapsack問題でdpと言われれば重みをindexとするdp。
しかし今回は色の制約が存在する。これを愚直に持つと$O(NW2^C)$となる。
そこでこの使った色の情報を、処理の順序を工夫し、同じ色の荷物をまとめて更新することで対処する。

$c$色使って重み$w$の時の価値の最大値を${\rm dp}\_{c,w}$としてdpする。
ある色$c_i$の荷物に関して、新規に${\rm dp}'\_{c,w}$という表を作る。
これは$c_i$と$c-1$色使ったときの値が${\rm dp}'\_{c,w}$となる。
${\rm dp}'\_{c,w} \gets {\rm max} \\{ {\rm dp}'\_{c,w}, {\rm dp}'\_{c,w-w_i}+v_i, {\rm dp}\_{c-1,w-w_i}+v_i \\}$として更新する。
そして${\rm dp}\_{c,w} \gets {\rm max} \\{ {\rm dp}\_{c,w}, {\rm dp}'\_{c,w} \\}$とすれば、その色に関する更新となる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
const int C_NUM = 50; // the number of colors
struct item_t { int w, v, c; };
bool operator < (item_t a, item_t b) { return a.c < b.c; }
int main() {
    int n, w_max, c_max; cin >> n >> w_max >> c_max;
    vector<vector<item_t> > xss(C_NUM);
    repeat (i,n) {
        item_t x; cin >> x.w >> x.v >> x.c;
        xss[x.c-1].push_back(x);
    }
    vector<vector<int> > dp(c_max+1, vector<int>(w_max+1));
    for (auto & xs : xss) {
        vector<vector<int> > ndp(c_max+1, vector<int>(w_max+1));
        for (auto x : xs) {
            repeat (i,c_max) {
                repeat_reverse (j, w_max+1 - x.w) {
                    ndp[i+1][j+x.w] = max(ndp[i+1][j+x.w], max(ndp[i+1][j] + x.v, dp[i][j] + x.v));
                }
            }
        }
        repeat (i,c_max+1) {
            repeat (j,w_max+1) {
                dp[i][j] = max(dp[i][j], ndp[i][j]);
            }
        }
    }
    int ans = 0;
    repeat (i,c_max+1) ans = max(ans, *max_element(dp[i].begin(), dp[i].end()));
    cout << ans << endl;
    return 0;
}
```
