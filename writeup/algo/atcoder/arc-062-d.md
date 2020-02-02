---
layout: post
alias: "/blog/2016/10/15/arc-062-d/"
date: "2016-10-15T23:54:56+09:00"
title: "AtCoder Regular Contest 062 D - AtCoDeerくんと変なじゃんけん / AtCoDeer and Rock-Paper"
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc062/tasks/arc062_b" ]
---

貪欲っぽいという直感により何も考えず投げてみたら通ったやつ。何故通ったかは分からなかったが、本番中なので通ればよし。

%20さんによる[sedの提出](https://beta.atcoder.jp/contests/arc062/submissions/931610)や[perl golf](https://beta.atcoder.jp/contests/arc062/submissions/930469)がよかったので見ておきたい。

## implementation

``` c++
#include <iostream>
using namespace std;
int main() {
    string s; cin >> s;
    int ans = 0;
    int margin = 0;
    for (char c : s) {
        if (c == 'g') {
            if (not margin) {
                ++ margin;
            } else {
                -- margin;
                ++ ans;
            }
        } else if (c == 'p') {
            if (not margin) {
                ++ margin;
                -- ans;
            } else {
                -- margin;
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```
