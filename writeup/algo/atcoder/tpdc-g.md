---
layout: post
alias: "/blog/2016/01/19/tpdc-g/"
title: "Typical DP Contest G - 辞書順"
date: 2016-01-19T17:24:02+09:00
tags: [ "comepetitive", "writeup", "atcoder", "dp", "typical-dp-contest", "reconstruct", "overflow" ]
---

dpは苦手。
解説を見た。

## [G - 辞書順](https://beta.atcoder.jp/contests/tdpc/tasks/tdpc_lexicographical)

### 解法

DP + 復元。$O(\|s\|)$。

まず、$i$文字目を先頭とする部分列の数${\rm dp}\_i$を求める。
$i$文字目より後に初めて文字$c$が出現する位置を$j\_{i,c}$とすると、${\rm dp}\_i = 1 + \Sigma\_{c \in ``abcde \dots z"} {\rm dp}\_{j\_{i,c}}$となる。
普通に計算すると明かにoverflowするが、$k$より大きい値は区別する必要がないので適当に`min`を取ればよい。

次に、これの経路復元をする。
$i$文字目が使われることが分かっていて、${\rm dp}\_i = 1 + a + b + c + \dots + z$としたとき、$i$文字目を先頭とする$k$番目の部分列を考える。
$s_i$が使われるのは当然として、それ以降の文字列は、

-   $k = 1$なら、空文字列
-   $1 \lt k \le 1+a$なら、$j\_{i,a}$番目の文字を先頭とする部分列で$k-1$番目のもの
-   $1+a \lt k \le 1+a+b$なら、`$j\_{i,b}$番目の文字を先頭とする部分列で$k-1-a$番目のもの
-   $\dots$
-   $1+a+b+c+\dots+z \lt k$なら、存在しない

となる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
int main() {
    string s; ll k; cin >> s >> k;
    int n = s.size();
    vector<array<ll,26> > next(n+1);
    repeat (j,26) next[n][j] = n;
    repeat_reverse (i,n) repeat (j,26) next[i][j] = s[i]-'a' == j ? i : next[i+1][j];
    // dp
    vector<ll> dp(n+1);
    repeat_reverse (i,n) {
        dp[i] = 1;
        repeat (j,26) {
            dp[i] = min(k+1, dp[i] + dp[next[i+1][j]]);
        }
    }
    // reconstruct
    string t;
    int i = -1;
    while (k > 0) {
        k -= 1;
        int j = 0;
        for (; j < 26; ++j) {
            int l = next[i+1][j];
            if (k >= dp[l]) {
                k -= dp[l];
            } else {
                t += 'a'+j;
                i = l;
                break;
            }
        }
        if (j == 26) break;
    }
    // output
    if (t.empty()) t = "Eel";
    cout << t << endl;
    return 0;
}
```
