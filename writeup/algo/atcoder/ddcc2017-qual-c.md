---
layout: post
alias: "/blog/2017/11/10/ddcc2017-qual-c/"
date: "2017-11-10T23:34:01+09:00"
title: "DISCO presents ディスカバリーチャンネル コードコンテスト2017 予選: C - 収納"
tags: [ "competitive", "writeup", "atcoder", "ddcc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2017-qual/tasks/ddcc2017_qual_c" ]
---

## solution

貪欲ぽく。
残っているなかで最も大きいのと最も小さいのを対にしていく。$O(N)$。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int main() {
    // input
    int n, c; scanf("%d%d", &n, &c);
    vector<int> l(n); repeat (i, n) scanf("%d", &l[i]);
    // solve
    sort(whole(l));
    int cnt = 0;
    int i = 0, j = n - 1;
    while (i < j) {
        while (i < j and l[i] + l[j] + 1 <= c) {
            ++ i;
            -- j;
            ++ cnt;
        }
        -- j;
    }
    // output
    int result = n - cnt;
    printf("%d\n", result);
    return 0;
}
```
