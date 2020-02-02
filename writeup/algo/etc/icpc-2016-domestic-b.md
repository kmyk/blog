---
layout: post
alias: "/blog/2016/06/27/icpc-2016-domestic-b/"
title: "ACM-ICPC 2016 国内予選 B: 当選者を探せ!"
date: 2016-06-27T13:01:51+09:00
tags: [ "competitive", "writeup", "icpc" ]
---

-   <http://icpcsec.storage.googleapis.com/icpc2016-domestic/problems/all_ja.html#section_B>
-   <http://icpc.iisf.or.jp/past-icpc/domestic2016/judgedata/B/>

## solution

丁寧にやる。投票を順番に処理していって、都度確定したか確認すればよい。
投票数$n$候補者数$k$として$O(nk)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    while (true) {
        int n; cin >> n;
        if (n == 0) break;
        vector<char> c(n); repeat (i,n) cin >> c[i];
        array<int,26> cnt = {};
        int i;
        for (i = 0; i < n; ++ i) {
            int remaining = n-i-1;
            cnt[c[i] - 'A'] += 1;
            int cnt_max = *whole(max_element, cnt);
            if (whole(count_if, cnt, [&](int a) { return cnt_max <= a + remaining; }) == 1) {
                break;
            }
        }
        auto it = whole(max_element, cnt);
        if (whole(count, cnt, *it) == 1) {
            cout << char('A' + (it - cnt.begin())) << ' ' << i+1 << endl;
        } else {
            cout << "TIE" << endl;
        }
    }
    return 0;
}
```
