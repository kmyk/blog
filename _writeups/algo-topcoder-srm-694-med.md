---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-694-med/
  - /blog/2016/07/10/srm-694-med/
date: "2016-07-10T19:17:38+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp" ]
---

# TopCoder SRM 694 Div1 Medium: DistinguishableSetDiv1

rolling hashでなんとか間に合うかなと思ったが落ちた。零完つらい。

## problem

$N$人($N \le 1000$)の人間と$M$問($M \le 20$)の$26$択の質問があって、それぞれの人間のそれぞれの質問への解答$a : N \times M \to 26$が与えられる。
問題の集合$X \in \mathcal{P}(M)$に対しその問題集合$X$が全ての人間を区別可能とは、任意の異なる$2$人の人間$i, j \in N$に対し、ある問題$k \in X$があって、その問題への解答が異なる$a(i,k) \ne a(j,k)$時である。
全ての人間を区別可能な問題集合の総数を答えよ。

## solution

DP. $O(N^2 + M2^M)$.

For two people $i, j$, think the problems which cannot distinguish them.
Such problem sets are $\\{ k \in M \mid a(i,k) = a(j,k) \\}$ or the subsets.
So you sholud enumerate such problem sets for all pairs of people, and count sets which is not a subset of the sets.
You can count this with bit-DP, propagating non-distinguishable flags recursively.

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
class DistinguishableSetDiv1 { public: int count(vector<string> answer); };

int DistinguishableSetDiv1::count(vector<string> a) {
    int n = a.size();
    int m = a.front().size();
    vector<bool> dp(1<<m, true); // is_distinguishable
    repeat (i,n) repeat (j,i) {
        int s = 0;
        repeat (k,m) if (a[i][k] == a[j][k]) s |= 1<<k;
        dp[s] = false;
    }
    repeat_reverse (s,1<<m) if (not dp[s]) {
        repeat (i,m) if (s & (1<<i)) {
            dp[s ^ (1<<i)] = false;
        }
    }
    return whole(std::count, dp, true);
}
```
