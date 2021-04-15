---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-694-easy/
  - /blog/2016/07/10/srm-694-easy/
date: "2016-07-10T19:17:35+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "xor" ]
---

# TopCoder SRM 694 Div1 Easy: TrySail

配列長を$256$でなく$255$で取ってて死んだ。
とてもつらい。

## problem

長さ$N$の数列$a_i$が与えられる。。$3 \le N \le 50$。この各要素を$3$組に分類する。空の組を作ってはいけない。そのように分類したとき、それぞれの組の排他的論理和による総和の算術による総和を最大化し、その値を答えよ。

つまり$\mathrm{ans} = \max\_{f : N \to 3, f^{-1}(x) \ne \emptyset} \Sigma\_{i \lt 3}^{\text{plus}} \Sigma\_{j \lt f^{-1}(i)}^{\text{xor}} a_j$ for given $a_i$。

## solution

DP. $O(A^2)$, $A = 256$ is the maximum of elements.

At first, think the simple DP.
The function is $\mathrm{dp} : 256 \times 256 \times 256 \times \mathcal{P}(3) \to 2$, the arguments are xor-sum of each group and empty-flags of groups, and the value is whether such a state exists or not. This is updated for each $a_i$, $N$ times.

Let's reduce the complexity.

-   To make empty group is obviously wrong choice to maximize the sum, so we can ignore the restriction.
-   When the xor-sums of two groups are known, the xor-sum of the rest group is easily computable. Let $s_0, s_1$ be the known xor-sums, then the unknown xor-sum $s_2 = \Sigma_i^{\text{xor}} a_i \oplus s_0 \oplus s_1$.

So we can do the DP on the function $\mathrm{dp} : 256 \times 256 \to 2$.
And the $\mathrm{ans} = \max \\{ s_0 + s_1 + (\Sigma_i^{\text{xor}} a_i \oplus s_0 \oplus s_1) \mid \mathrm{dp}(s_0, s_1) = 1 \\}$.

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
class TrySail { public: int get(vector<int> strength); };

int TrySail::get(vector<int> strength) {
    array<array<array<bool,256>,256>,2> dp = {};
    array<array<bool,256>,256> & cur = dp[0];
    array<array<bool,256>,256> & prv = dp[1];
    int acc = 0; for (int x : strength) acc ^= x;
    cur[0][0] = true;
    for (int x : strength) {
        cur.swap(prv);
        repeat (i,256) {
            repeat (j,256) {
                cur[i][j] = false;
            }
        }
        repeat (i,256) {
            repeat (j,256) {
                if (prv[i][j]) {
                    cur[i^x][j] = true;
                    cur[i][j^x] = true;
                    cur[i][j] = true;
                }
            }
        }
    }
    int ans = -1;
    repeat (i,256) {
        repeat (j,256) {
            if (cur[i][j]) {
                setmax(ans, i+j+(acc^i^j));
            }
        }
    }
    return ans;
}
```
