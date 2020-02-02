---
layout: post
alias: "/blog/2016/10/10/jag2016autumn-e/"
date: "2016-10-10T21:51:36+09:00"
title: "JAG Practice Contest for ACM-ICPC Asia Regional 2016: E - Similarity of Subtrees"
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc", "rolling-hash", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016autumn/tasks/icpc2016autumn_e" ]
---

本番でバグらせて泥沼化したときの対処をどうするか、という話になった。
気付いた時点で全員手を止めリファクタリング等を兼ねて違う人が書き直すのはどうかという結論。

## problem

根付き木$T$に関してその深さ$d$の位置の頂点の数を$S(T,d)$と書くとする。
木$T_1$と$T_2$がsimilarとは、$\forall d \in \mathbb{N}. S(T_1,d) = S(T_2,d)$とする。
木$T$が与えられるので、その部分木でsimilarな対の数を数えよ。

## solution

rolling hash。$O(N \log N)$。

木$T$に対し列$(S(T,0), S(T,1), S(T,2), \dots)$を作り、そのhash値の重複を数えればよい。
これを単純にやると列の長さも$N$になるので$O(N^2)$かかる。
子のそれぞれに関して列$l(T_i) = (S(T_i,0), S(T_i,1), S(T_i,2), \dots)$であるとき、その親の列$l(T) = (1, \Sigma_i S(T_i,0), \Sigma_i S(T_i,1), \Sigma_i S(T_i,2), \dots)$である。
各点での加算が必要であるが、ここでrolling hashの性質を思い出す。
rolling hashは列に対するhash関数で、適当な$p, q \in \mathbb{N}$に対し$H(a_0, a_1, a_2, \dots, a_n) \equiv a_0 + a_1p + a_2p^2 + \dots + a_np^{n-1} \pmod q$であった。
つまり単純に$H(T) \equiv (\Sigma_i H(T_i))p + 1 \pmod q$とでき、間に合う。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; cin >> a >> b; -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<uint64_t> hash(n); {
        const uint64_t p = 1e9+7;
        function<uint64_t (int, int)> dfs = [&](int i, int parent) {
            uint64_t acc = 0;
            for (int j : g[i]) if (j != parent) {
                acc += dfs(j, i);
            }
            return hash[i] = acc * p + 1;
        };
        dfs(0, -1);
    }
    map<uint64_t, int> cnt;
    repeat (i,n) cnt[hash[i]] += 1;
    ll ans = 0;
    for (auto it : cnt) {
        ans += it.second *(ll) (it.second - 1) / 2;
    }
    cout << ans << endl;
    return 0;
}
```
