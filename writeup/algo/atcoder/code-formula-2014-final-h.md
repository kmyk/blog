---
layout: post
alias: "/blog/2017/02/22/code-formula-2014-final-h/"
date: "2017-02-22T23:44:38+09:00"
tags: [ "competitive", "writeup", "atcoder", "codeformula", "lie", "loop-unrolling" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-formula-2014-final/tasks/code_formula_2014_final_h" ]
---

# Code Formula 2014 本選: H - 平和協定

この大会は予選通ったがこの本戦は交通費支給が渋かったので蹴った記憶がある。
そしてそういう人が多かったのか次の年から開催が消えてしまった。

## solution

loop unrollingする。$O(N^2)$。

## implementation

多めに空間をとって踏んでも結果に影響しない値で埋めておくと楽。clangで提出しないと(たとえ`#pragma GCC ...`しても)TLEる。

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
#define MAX_N 50000
const int inf = 1e9+7;
int a[MAX_N + 10];
int b[MAX_N + 10];
int main() {
    repeat (x, MAX_N + 10) a[x] = b[x] = inf;
    int n, s1, s2; scanf("%d%d%d", &n, &s1, &s2);
    repeat (i,n) scanf("%d%d", &a[i], &b[i]);
    int cnt = 0;
    repeat (x,n) {
        for (int y = x+1; y < n; y += 8) {
            ll d0 = (a[x] - a[y  ]) *(ll) (b[x] - b[y  ]);
            ll d1 = (a[x] - a[y+1]) *(ll) (b[x] - b[y+1]);
            ll d2 = (a[x] - a[y+2]) *(ll) (b[x] - b[y+2]);
            ll d3 = (a[x] - a[y+3]) *(ll) (b[x] - b[y+3]);
            ll d4 = (a[x] - a[y+4]) *(ll) (b[x] - b[y+4]);
            ll d5 = (a[x] - a[y+5]) *(ll) (b[x] - b[y+5]);
            ll d6 = (a[x] - a[y+6]) *(ll) (b[x] - b[y+6]);
            ll d7 = (a[x] - a[y+7]) *(ll) (b[x] - b[y+7]);
            if (s1 <= d0 and d0 <= s2) ++ cnt;
            if (s1 <= d1 and d1 <= s2) ++ cnt;
            if (s1 <= d2 and d2 <= s2) ++ cnt;
            if (s1 <= d3 and d3 <= s2) ++ cnt;
            if (s1 <= d4 and d4 <= s2) ++ cnt;
            if (s1 <= d5 and d5 <= s2) ++ cnt;
            if (s1 <= d6 and d6 <= s2) ++ cnt;
            if (s1 <= d7 and d7 <= s2) ++ cnt;
        }
    }
    printf("%d\n", cnt);
    return 0;
}
```
