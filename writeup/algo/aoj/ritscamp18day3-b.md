---
layout: post
alias: "/blog/2018/04/02/aoj-ritscamp18day3-b/"
title: "AOJ RitsCamp18Day3: B. 階層的計算機 (Hierarchical Calculator)"
date: "2018-04-02T22:46:46+09:00"
tags: [ "competitive", "writeup", "aoj", "rupc", "greedy" ]
"target_url": [ "https://onlinejudge.u-aizu.ac.jp/beta/room.html#RitsCamp18Day3/problems/B" ]
---

## solution

$2$があれば全て使う。$-2$はふたつ対にして貪欲に使う。$-2$が余っているとき$-1$があるなら対にして使う。$O(N)$

## note

-   editorial: <https://www.slideshare.net/hcpc_hokudai/rupc-2018-day3-b-hierarchical-calculator>
-   某合宿 day2 no1 b
-   誤読した。添字の列$s\_1, s\_2, \dots, s\_m$として辞書順最小を求めるところを、部分列$a\_{s\_1}, a\_{s\_2}, \dots, a\_{s\_m}$として辞書順最小だと勘違いした。
-   誤読したまま実装のミスにより本来の題意に沿った実装をしてしまいAC

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

vector<int> realize(int n, vector<int> const & a, vector<bool> const & used) {
    vector<int> s;
    REP (i, n) if (used[i]) {
        s.push_back(i);
    }
    return s;
}

vector<int> solve(int n, vector<int> const & a) {
    vector<bool> used(n);
    int minus_two = 0;
    bool minus_one = false;
    REP (i, n) {
        switch (a[i]) {
            case  2: used[i] = true; break;  // use 2
            case  1: /* nop */ break;
            case  0: /* nop */ break;
            case -1: minus_one = true; break;
            case -2: minus_two += 1; break;
            default: assert (false);
        }
    }
    if (minus_two % 2 == 0) {
        minus_one = false;
    } else {
        if (not minus_one) {
            minus_two -= 1;
        }
    }
    // use -2
    int i = 0;
    while (minus_two --) {
        while (a[i] != -2) ++ i;
        used[i] = true;
        ++ i;
    }
    // use -1
    if (minus_one) {
        vector<bool> nused;
        REP (i, n) if (a[i] == -1) {
            if (nused.empty() or realize(n, a, used) < realize(n, a, nused)) {
                nused = used;
                nused[i] = true;
            }
        }
        used = nused;
    }
    return realize(n, a, used);
}

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);
    vector<int> result = solve(n, a);
    printf("%d\n", int(result.size()));
    for (int i : result) printf("%d\n", i + 1);
    return 0;
}
```
