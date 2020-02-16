---
layout: post
redirect_from:
  - /blog/2018/03/31/codechef-cook91-csubseq/
date: "2018-03-31T02:13:03+09:00"
tags: [ "competitive", "writeup", "codechef", "dp" ]
"target_url": [ "https://www.codechef.com/COOK91/problems/CSUBSEQ" ]
---

# CodeChef February Cook-Off 2018: Chef and Chefness

## problem

部分列として出現する `chef` の数を文字列のchefnessと呼ぶ。
文字列$S$から適当に文字を削除してそのchefnessをちょうど$K$にしたい。
最小で何文字の削除が必要か。

## solution

`map<array<int, 4>, int>` でDP。ちゃんと状態を圧縮する。$O(NK^4)$で抑えられるが正確な計算量は分からず。

$K \le 32$と小さい。
部分列 `c` `ch` `che` `chef` の数$(c, h, e, f)$をそれぞれ状態に持つことを考える。
$f \gt K$のときは$f = \infty$にまとめてよい。$e + f \gt K$のときも$e = \infty$と同じである。
同様に$h + e + f$と$c + h + e + f$についても潰せば、状態数はかなり減る。
そのため$\mathrm{dp}(i, c, h, e, f)$の形のDPで間に合う。

## note

定数倍が悪いと通らない。少し多めに実装すれば`map`を回避することもできるぽい。

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

int solve(int n, int k, string const & s) {
    const int inf = k + 1;
    map<array<int, 4>, int> cur;
    cur[array<int, 4>()] = 0;
    for (char c : s) {
        int i = string("chef").find(c);
        map<array<int, 4>, int> prv = cur;
        for (auto it : prv) {
            array<int, 4> dp = it.first;
            int len = it.second;
            dp[i] += (i == 0 ? 1 : dp[i - 1]);
            if (dp[3] > k) continue;
            if (dp[2] + dp[3] > k) dp[2] = inf;
            if (dp[1] + dp[2] + dp[3] > k) dp[1] = inf;
            if (dp[0] + dp[1] + dp[2] + dp[3] > k) dp[0] = inf;
            chmax(cur[dp], len + 1);
        }
    }
    int max_len = -1;
    for (auto it : cur) {
        array<int, 4> dp = it.first;
        int len = it.second;
        if (dp[3] == k) {
            chmax(max_len, len);
        }
    }
    return max_len == -1 ? -1 : n - max_len;
}

int main() {
    int t; cin >> t;
    while (t --) {
        int n, k; cin >> n >> k;
        string s; cin >> s;
        int result = solve(n, k, s);
        cout << result << endl;
    }
    return 0;
}
```
