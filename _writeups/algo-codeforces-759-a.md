---
layout: post
redirect_from:
  - /writeup/algo/codeforces/759-a/
  - /blog/2018/03/31/cf-759-a/
date: "2018-03-31T01:27:46+09:00"
tags: [ "competitive", "writeup", "codeforces", "permutation", "minimize" ]
"target_url": [ "http://codeforces.com/contest/759/problem/A" ]
---

# Codeforces Round #393 (Div. 1) (8VC Venture Cup 2017 - Final Round Div. 1 Edition): A. Pavel and barbecue

## problem

バーベキューをしている。
串が$n$本あり、$i$番目の串は$y = i$の位置に$x$軸と平行に右向きで置いてある。
置換$p \in \mathfrak{S}\_n$と配列$b : n \to 2$が与えられる。
毎秒ごとに串をその位置$y$により$p$に従って入れかえ$b$に従って反転する。
十分大きな有限秒後に全ての串について「任意の位置に任意の向きで一度以上存在したことがある」を満たすように$p, b$を修正するとき、その修正に必要な要素数の最小値を答えよ。

## solution

全体がひとつの有向閉路になるように$p$を修正する。
$b\_i = 1$な$i$が奇数個になるよう$p$を修正する。$O(n)$。

## note

-   某合宿 day1 no1 div1 A
-   問題文が難しい 1

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> p(n);
    REP (i, n) {
        scanf("%d", &p[i]);
        -- p[i];
    }
    vector<bool> b(n);
    REP (i, n) {
        int b_i; scanf("%d", &b_i);
        b[i] = b_i;
    }

    // solve
    vector<bool> used(n);
    function<void (int)> go = [&](int i) {
        used[i] = true;
        if (not used[p[i]]) {
            go(p[i]);
        }
    };
    int cycles = 0;
    REP (i, n) {
        if (not used[i]) {
            ++ cycles;
            go(i);
        }
    }
    int sum_b = accumulate(ALL(b), 0);
    int result = (cycles == 1 ? 0 : cycles) + (sum_b % 2 == 0);

    // output
    printf("%d\n", result);
    return 0;
}
```
