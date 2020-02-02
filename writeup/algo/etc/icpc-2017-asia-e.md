---
layout: post
alias: "/blog/2017/12/19/icpc-2017-asia-e/"
title: "AOJ 1382 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: E. Black or White"
date: "2017-12-19T03:49:19+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia", "range-min-query" ]
---

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1382>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=E>

## problem

`B` `W`からなる同じ長さの文字列$s, t$が与えられる。
整数$k$が固定される。
$s$中の長さ$k$以下の部分文字列を全て`B`あるいは`W`で塗り潰す操作を考える。
文字列$s$を$t$にするのに必要な操作回数の最小値を答えよ。

## solution

塗り潰す区間についての観察。実家DP。$O(n)$。

区間$I\_1 = [l\_1, r\_1), I\_2$ = [l\_2, r\_2)について塗り潰すとき(順序は適当に入れ換えて)$I\_1 \subseteq I\_2$ (特に$l\_2 \lt l\_1$かつ$r\_1 \lt r\_2$)あるいは$I\_1 \cap I\_2 = \emptyset$である。
そうでなければ交差しないように操作を取り直せるため。
これにより黒白を交互にピラミッド状に塗る操作のみを考えればよい。
これはそのような区間中の`B` `W`の入れ替わりの回数のおよそ半分の操作回数で塗れる。
ここまで分かれば$O(n^2)$のDP。
さらに区間min queryに答えられるデータ構造を用いれば$O(n)$や$O(n \log n)$に落とせる。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;

template <typename T, class Compare = less<T> >
struct sliding_window {
    deque<pair<int, T> > data;
    function<bool (T const &, T const &)> compare;
    sliding_window(Compare const & a_compare = Compare()) : compare(a_compare) {}
    T front() { return data.front().second; }  // O(1), minimum
    void push_back(int i, T a) { while (not data.empty() and compare(a, data.back().second)) data.pop_back(); data.emplace_back(i, a); }  // O(1) amortized.
    void pop_front(int i) { if (data.front().first == i) data.pop_front(); }
    void push_front(int i, T a) { if (data.empty() or not compare(data.front().second, a)) data.emplace_front(i, a); }
};

constexpr int inf = 1e9 + 7;
int main() {
    // input
    int n, k; cin >> n >> k;
    string s, t; cin >> s >> t;
    // solve
    vector<int> delta(n + 1);
    REP (i, n) {
        delta[i + 1] = delta[i] + (i == 0 or t[i - 1] != t[i]);
    }
    vector<int> dp(n + 1, inf);
    sliding_window<int> sw_b, sw_w;
    dp[0] = 0;
    sw_b.push_back(0, 2 * dp[0] - delta[0] + (t[0] == 'B'));
    sw_w.push_back(0, 2 * dp[0] - delta[0] + (t[0] == 'W'));
    REP3 (r, 1, n + 1) {
        if (r - k - 1 >= 0) {
            sw_b.pop_front(r - k - 1);
            sw_w.pop_front(r - k - 1);
        }
        dp[r] = (s[r - 1] == t[r - 1]) ?
            dp[r - 1] :
            ((t[r - 1] == 'W' ? sw_b : sw_w).front() + delta[r]) / 2 + 1;
        if (r < n) {
            sw_b.push_back(r, 2 * dp[r] - delta[r] + (t[r] == 'B'));
            sw_w.push_back(r, 2 * dp[r] - delta[r] + (t[r] == 'W'));
        }
    }
    // output
    cout << dp[n] << endl;
    return 0;
}
```
