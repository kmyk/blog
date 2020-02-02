---
layout: post
alias: "/blog/2016/05/13/tco-2016-round-2a-easy/"
title: "TopCoderOpen 2016 Round 2A Easy: LCMGCD"
date: 2016-05-13T02:04:10+09:00
tags: [ "competitive", "writeup", "topcoder", "tco" ]
---

零完。私も早く赤くなりたい。

## problem

$x_i = 2^p3^q, (p, q \ge 0)$の形をした整数のみからなる数列$x$が与えられる。
整数$t = 2^p3^q$が与えられる。
以下の操作を繰り返して、整数$t$のみからなる長さ$1$の数列を作れるかどうか答えよ。

-   数列から数を2つ選び、そのgcd/lcmの好きな方を取り、数列に戻す。

## solution

Simple search on $4^9$.

The numbers $x_i$ in the list can be classfied into $3 \times 3$ groups, by comparing the exponents with $t$.
For example, when $t = 16 = 2^4$, you can see $x_i = 32 = 2^5, x_j = 64 = 2^6$ as a same number.
Each group are indexed as $(p, q)$ where $p, q \in \\{ LT, EQ, GT \\}$, so the number of groups is $9$.

For each group $(p, q)$, count the number of such numbers $x_i$s in $x$.
You can search over the space with the size $n^9$, but it's still large.

If the too many numbers in the same group, almost all of them are mostly ignored.
So, for each group, you can consider the size of the group as one that cannot exceed the $4$.
i.e. you should search over only the space, with the size is $4^9$.

## implementation

``` c++
#include <bits/stdc++.h>
#include <functional>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
class LCMGCD { public: string isPossible(vector<int> x, int t); };

pair<int,int> factorize(int x) {
    int p = 0; while (x % 2 == 0) { x /= 2; ++ p; }
    int q = 0; while (x % 3 == 0) { x /= 3; ++ q; }
    return { p, q };
}
const int LT = 0;
const int EQ = 1;
const int GT = 2;
int lcm(int a, int b) { return min(a / 3, b / 3) * 3 + min(a % 3, b % 3); }
int gcd(int a, int b) { return max(a / 3, b / 3) * 3 + max(a % 3, b % 3); }
string LCMGCD::isPossible(vector<int> xs, int t) {
    vector<int> types(9); {
        int tp, tq; tie(tp, tq) = factorize(t);
        for (int x : xs) {
            int p, q; tie(p, q) = factorize(x);
            int a = p < tp ? LT : tp < p ? GT : EQ;
            int b = q < tq ? LT : tq < q ? GT : EQ;
            types[a * 3 + b] += 1;
        }
    }
    repeat (i,9) setmin(types[i], 4);
    bool ans = false;
    set<vector<int> > used;
    int n = accumulate(types.begin(), types.end(), 0);
    function<void ()> dfs = [&]() {
        if (used.count(types)) return;
        used.insert(types);
        if (n == 1 and types[EQ * 3 + EQ]) ans = true;
        repeat (i,9) if (types[i]) {
            types[i] -= 1;
            repeat (j,i+1) if (types[j]) {
                types[j] -= 1;
                n -= 1;
                {
                    types[lcm(i, j)] += 1;
                    dfs();
                    types[lcm(i, j)] -= 1;
                }
                {
                    types[gcd(i, j)] += 1;
                    dfs();
                    types[gcd(i, j)] -= 1;
                }
                n += 1;
                types[j] += 1;
            }
            types[i] += 1;
        }
    };
    dfs();
    return ans ? "Possible" : "Impossible";
}
```
