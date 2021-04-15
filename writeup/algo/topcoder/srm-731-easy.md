---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-731-easy/
  - /blog/2018/03/18/srm-731-easy/
date: "2018-03-18T03:19:41+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "tree" ]
---

# TopCoder SRM 731 Easy. TreesAndBrackets

## problem

子の順序を区別する根付き木$t\_1, t\_2$が与えられる。
$t\_1$の葉を削除する操作を繰り返して$t\_2$と一致させられるか判定せよ。
ただし木はbalanceした括弧の形で表現される。

## solution

DP。$t\_1, t\_2$のそれぞれ$i, j$文字目まで消費する構築の過程があるかどうかを$\mathrm{dp}(i, j) \in 2$とする。$O(\|t\_1\| \cdot \|t\_2\|)$。

## note

$O(N^2)$思考停止DPしてしまったけど貪欲ぽくして$O(N)$で済むはず。
両端の`(`と`)`を除去すると木の列になってそのmatchingをする問題になる。
この両端を除去する操作は再帰的にでき、交換はなしだから端から順に貪欲に対にしていける。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
typedef long long ll;
using namespace std;
class TreesAndBrackets { public: string check(string t1, string t2); };

string TreesAndBrackets::check(string t1, string t2) {
    int l1 = t1.length();
    int l2 = t2.length();
    vector<int> match(l1, -1); {
        stack<int> stk;
        REP (i, l1) {
            if (t1[i] == '(') {
                stk.push(i);
            } else {
                int j = stk.top(); stk.pop();
                match[i] = j;
                match[j] = i;
            }
        }
    }
    vector<vector<bool> > dp(l1 + 1, vector<bool>(l2 + 1));
    dp[0][0] = true;
    REP (i, l1) REP (j, l2) if (dp[i][j]) {
        if (t1[i] == t2[j]) {
            dp[i + 1][j + 1] = true;
        }
        if (t1[i] == '(') {
            dp[match[i] + 1][j] = true;
        }
    }
    bool result = dp[l1][l2];
    return result ? "Possible" : "Impossible";
}
```
