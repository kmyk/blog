---
layout: post
title: "NJPC2017: C - ハードル走"
date: 2018-07-12T20:51:19+09:00
tags: [ "competitive", "writeup", "atcoder", "njpc" ]
"target_url": [ "https://beta.atcoder.jp/contests/njpc2017/tasks/njpc2017_c" ]
---

## note

[editorial](https://drive.google.com/drive/folders/0BziHwCcP5FcyejdCaFVibmlidFE)を見て解いた。

「この位置にハードル」「ここに着地可能」「この位置でジャンプしたい」などをイベントとして`priority_queue`で管理すればできると思ったが3ケースだけWAが出て失敗。
バグなのか嘘解法なのかは不明。
出力が1bitなので、本番なら黒魔術で通してたと思う。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

bool solve(int n, int l, const vector<int> & x) {
    vector<pair<int, int> > ranges;
    for (int i = 0; i < n; ) {
        int lo = x[i];
        int hi = x[i];
        ++ i;
        while (i < n and x[i] <= hi + l) {
            hi = x[i];
            ++ i;
        }
        ranges.emplace_back(lo, hi);
        if (l <= hi - lo) {
            return false;
        }
    }
    int p = 0;
    for (auto range : ranges) {
        int lo, hi; tie(lo, hi) = range;
        if (lo <= p) return false;
        p = max(p + 2 * l, hi + l);
    }
    return true;
}

int main() {
    // input
    int n, l; cin >> n >> l;
    vector<int> x(n);
    REP (i, n) cin >> x[i];

    // solve
    bool ans = solve(n, l, x);

    // output
    cout << (ans ? "YES" : "NO") << endl;
    return 0;
}
```
