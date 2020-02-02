---
layout: post
alias: "/blog/2017/02/04/agc-010-c/"
date: "2017-02-04T23:05:35+09:00"
title: "AtCoder Grand Contest 010: C - Cleaning"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc010/tasks/agc010_c" ]
---

Aを書いた後それをBかCが書けたら投げようと思ったら、BもCも最後まで分からなかったので無提出rating変化なし。
あまり良くないとは思うのだけれど、短期的なratingを考えると十分選択肢に入る戦略なのでこうなってしまう。

木DPだとは思っていたが、各部分木を全てちょうど葉と同一視できるのに気付かず、その頂点が要求するパスの数の加減$L_i$と上限$R_i$で木DPしようとしていた。

## solution

木DP。部分木は葉と同一視できるので根が$A_i = 0$な葉と見做せるかを答える。$O(N)$。

ある葉でない部分木$i$を葉と同一視するとして持つ石の数$A'\_i$を考える。
子は全て葉としてよい。
子の持つ石の総和$\mathrm{sum} = \sum\_{j \in \mathrm{children}(i)} A_j$とする。
この部分木の中で閉じたパスの数を$b$、外へ出ていくパスの数を$c$とすると、$A_i = b + c$かつ$\mathrm{sum} = 2b + c$である。
これは連立方程式として解けて$b = \mathrm{sum} - A_i$。一意に定まることに注意。
また$c = A_i - b$は求めたい$A'\_i$と等しい。
ここでそのような$(b, c)$がパスの張り方として有効かどうかの確認が必要。
$0 \le b, 0 \le c$に加えて、内部で$b$本張れるかを見れば十分。
子で$A_j$が最も大きいものを$j$として、$A_j \ge \frac{\mathrm{sum}}{2}$であればこの子が制限をして$b \le \mathrm{sum} - A_j$である必要がある。
そうでないとすると、単に$\mathrm{sum}$が制限をして$b \le \frac{\mathrm{sum}}{2}$を確認すればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
bool solve(int n, vector<int> & a, vector<vector<int> > & g) {
    vector<int> dp(n);
    auto is_leaf = [&](int i) { return g[i].size() == 1; };
    function<bool (int, int)> go = [&](int i, int parent) {
        if (is_leaf(i)) {
            dp[i] = a[i];
        } else {
            ll sum_dp = 0;
            for (int j : g[i]) if (j != parent) {
                if (not go(j, i)) return false;
                sum_dp += dp[j];
            }
            ll b = sum_dp - a[i];
            ll c = a[i] - b;
            if (b < 0 or c < 0) return false;
            int argmax_dp = *whole(max_element, g[i], [&](int j, int k) { return make_pair(j != i, dp[j]) < make_pair(k != i, dp[k]); });
            ll max_dp = dp[argmax_dp];
            if (max_dp > sum_dp / 2) {
                if (sum_dp - max_dp < b) return false;
            } else {
                if (sum_dp / 2 < b) return false;
            }
            dp[i] = c;
        }
        return true;
    };
    assert (n >= 2);
    if (n == 2) {
        return a[0] == a[1];
    } else {
        int i = 0;
        while (is_leaf(i)) ++ i;
        if (not go(i, -1)) return false;
        return dp[i] == 0;
    }
}
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int x, y; cin >> x >> y; -- x; -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    cout << (solve(n, a, g) ? "YES" : "NO") << endl;
    return 0;
}
```
