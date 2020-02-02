---
layout: post
alias: "/blog/2018/04/07/arc-094-e/"
title: "AtCoder Regular Contest 094: E - Tozan and Gezan"
date: "2018-04-07T23:01:46+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc094/tasks/arc094_c" ]
---

## solution

$A\_i \lt B\_i$なら$(A\_i, B\_i) \gets (0, B\_i - A\_i)$にしてよくて、差分の$B\_i - A\_i$を使って他の$A\_j \ge B\_j$な$A\_j$を減らして$A\_j \lt B\_j$を作れる。減らす$A\_j$の選択は雰囲気でいい感じにやる。$O(n \log n)$。

## note

-   雰囲気で通した 3
-   想定解「$A\_i \gt B\_i$な$i$があるならとざん君は$A\_i$を最後まで減らさないことでそれ以外をすべて$0$にできる」 それはそう どうして気付かなかったのか

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

ll solve(int n, vector<int> a, vector<int> b) {
    if (a == b) return 0;
    ll answer = 0;
    ll acc = 0;
    vector<int> ge;
    REP (i, n) {
        if (a[i] < b[i]) {
            answer += b[i];
            acc += b[i] - a[i];
            a[i] = 0;
            b[i] = 0;
        } else {
            if (b[i] != 0) {
                ge.push_back(i);
            }
        }
    }
    sort(ALL(ge), [&](int i, int j) { return b[i] > b[j]; });
    for (int i : ge) {
        if (acc < a[i] - b[i] + 1) continue;
        ll delta = min<ll>(acc, a[i] - b[i] + 1);
        a[i] -= delta;
        acc -= delta - 1;
        answer += b[i];
    }
    return answer;
}

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n), b(n);
    REP (i, n) {
        scanf("%d%d", &a[i], &b[i]);
    }
    ll answer = solve(n, a, b);
    printf("%lld\n", answer);
    return 0;
}
```
