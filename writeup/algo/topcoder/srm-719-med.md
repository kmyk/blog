---
layout: post
alias: "/blog/2017/08/15/srm-719-med/"
date: "2017-08-15T11:50:50+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm" ]
---

# TopCoder SRM 719 Div1 Medium: OwaskiAndTree

問題文中に `Overwatch` って単語が出てきてなんだっけとぐぐったら固有名詞 (ゲーム名)だった。

## problem

頂点に重みの付いた木上を歩く。
始めて訪ずれたときその重み分の点数を得る。点数が負になる場合は$0$に戻す。
根から始めて自由な位置で終了してよい。
点数の最大値を求めよ。

## solution

$0$に戻さない場合の値は木DPで明らか。
$0$に戻す操作は途中で負にすることを許してちょうど$1$回だけ行なうと見做せ、それをした後は戻さない場合のDPから求まる。そのようにすると木の根と葉全ての間のcutを決めてその下側だけ$0$に戻す操作なしで自由に使った場合の最大値になるので、これを木DP。$O(N)$。

## implementation

$2$回走らせてる再帰は明らかに融合できる。

``` c++
#include <bits/stdc++.h>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
class OwaskiAndTree { public: int maximalScore(vector<int> parent, vector<int> pleasure); };

constexpr int root = 0;
int OwaskiAndTree::maximalScore(vector<int> parent, vector<int> pleasure) {
    int n = pleasure.size();
    vector<vector<int> > children(n);
    repeat (i, n - 1) {
        children[parent[i]].push_back(i + 1);
    }
    vector<ll> acc(n); {
        function<void (int)> go = [&](int i) {
            acc[i] += pleasure[i];
            for (int j : children[i]) {
                go(j);
                if (acc[j] > 0) {
                    acc[i] += acc[j];
                }
            }
        };
        go(root);
    }
    vector<ll> dp(n); {
        function<void (int)> go = [&](int i) {
            for (int j : children[i]) {
                go(j);
                dp[i] += dp[j];
            }
            setmax(dp[i], acc[i]);
            setmax(dp[i], 0ll);
        };
        go(root);
    }
    return dp[root];
}
```
