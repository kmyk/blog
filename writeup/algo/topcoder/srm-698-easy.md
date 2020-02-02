---
layout: post
alias: "/blog/2016/09/18/srm-698-easy/"
date: "2016-09-18T02:32:25+09:00"
title: "TopCoder SRM 698 Div1 Easy: RepeatString"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp" ]
---

解くのが遅くて実質WA。
環境を更新後の初のするめだったらしくGreedのpathが通ってなくて手間取ってたのが悪いんだよきっと。

## solution

Each possible indices to split, do simple DP. $O(N^3)$.

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
class RepeatString { public: int minimalModify(string s); };

const int inf = 1e9+7;
int RepeatString::minimalModify(string s) {
    int n = s.length();
    int ans = (n+1)/2;
    repeat (sep,n+1) {
        string a = s.substr(0, sep);
        string b = s.substr(sep, string::npos);
        int al = a.length();
        int bl = b.length();
        vector<vector<int> > dp(al+1, vector<int>(bl+1, inf));
        dp[0][0] = 0;
        repeat (i,al+1) {
            repeat (j,bl+1) {
                if (j < bl) setmin(dp[i][j+1], dp[i][j] + 1); // insert
                if (i < al) setmin(dp[i+1][j], dp[i][j] + 1); // remove
                if (i < al and j < bl) setmin(dp[i+1][j+1], dp[i][j] + (a[i] != b[j])); // replace
            }
        }
        setmin(ans, dp[al][bl]);
    }
    return ans;
}
```
