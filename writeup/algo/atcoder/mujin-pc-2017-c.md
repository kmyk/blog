---
layout: post
alias: "/blog/2017/02/26/mujin-pc-2017-c/"
date: "2017-02-26T02:36:44+09:00"
title: "Mujin Programming Challenge 2017: C - Robot and String"
tags: [ "competitive", "writeup", "mujin-pc", "atcoder", "doubling", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/mujin-pc-2017/tasks/mujin_pc_2017_c" ]
---

$O(QN)$でなんとかならないかなと頑張ったが、少し無理があった。
$QN = 5 \times 10^{10}$とちょっと大きいのと配列を引く操作が多くて並列化も難しいのが敗因。

そもそも普通に解けるべき問題だったようにも見える。

## solution

空になる区間を前処理しておいて読み飛ばしていく。ダブリング。$O(Q \log N)$。

位置$l$に対し区間$[l,r)$が空になるような最小の$r \gt l$をそれぞれ求めておく。
これを$\mathrm{skip}(l) = r$とする。
この関数を用いればクエリ$[l,r)$に対し答えが`Yes`となるのは$\mathrm{skip}^k(l) = r$となるような$k$が存在すること。
この$k$の存在の判定は単純にやれば$O(N)$であるが、これはダブリングを用いれば$O(\log N)$となる。

関数$\mathrm{skip}$の計算について。
区間$[l,r)$が文字$c$のみになるような最小の$r \gt l$を$\mathrm{skip}\_c(l) = r$とおいて、これと共に求める。
$s_l = c$なら$\mathrm{skip}\_c(l) = l+1$、そうでないなら($c = \epsilon$を含めて)$\mathrm{skip}\_c(l) = \min \\{ \mathrm{skip}\_{\mathrm{pred}(c)}(l), \mathrm{skip}\_c(\mathrm{skip}(c)) \\}$。
これらは単純にはwell-foundedでないが、適当にすれば定まる。


## implementation

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int main() {
    string s; int q; cin >> s >> q;
    int n = s.length();
    auto dp = vectors(26+1, n, inf);
    repeat_reverse (i,n) {
        setmin(dp[s[i]-'a'][i], i+1);
        repeat (c,26) {
            if (dp[c][i] < n) {
                setmin(dp[c+1][i], dp[c][dp[c][i]]);
            }
        }
        if (dp[26][i] < n) {
            repeat (c,26) {
                setmin(dp[c][i], dp[c][dp[26][i]]);
            }
        }
    }
    int log_n = log2(n);
    auto skip = vectors(log_n+1, n, inf);
    skip[0] = dp[26];
    repeat (k,log_n) {
        repeat (i,n) {
            if (skip[k][i] < n) {
                skip[k+1][i] = skip[k][skip[k][i]];
            }
        }
    }
    while (q --) {
        int l, r; cin >> l >> r; -- l;
        int i = l;
        repeat_reverse (k, log_n+1) {
            while (i < n and skip[k][i] <= r) {
                i = skip[k][i];
            }
        }
        cout << (i == r ? "Yes" : "No") << endl;
    }
    return 0;
}
```
