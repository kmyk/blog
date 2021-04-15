---
redirect_from:
layout: post
date: 2018-07-02T20:13:40+09:00
tags: [ "competitive", "writeup", "atcoder", "codeflyer", "stack" ]
"target_url": [ "https://beta.atcoder.jp/contests/bitflyer2018-final-open/tasks/bitflyer2018_final_c" ]
---

# codeFlyer （bitFlyer Programming Contest）: C - 部分文字列と括弧

## solution

括弧列はnest深さの配列をsegment木とかで区間min取って二分探索する感じのが典型(典型)。
その方向で上手くやればできる。
しかも今回はよく見るとstack一本で十分(ありがち)で<span>$O(|S|)$</span>。

## implementation

``` c++
#include <bits/stdc++.h>
using ll = long long;
using namespace std;

int main() {
    // input
    string s; cin >> s;

    // solve
    map<int, int> stk;
    int nest = 0;
    ll answer = 0;
    for (char c : s) {
        if (c == '(') {
            stk[nest] += 1;
            ++ nest;
        } else {
            stk[nest] = 0;
            -- nest;
            answer += stk[nest];
        }
    }

    // output
    cout << answer << endl;
    return 0;
}
```
