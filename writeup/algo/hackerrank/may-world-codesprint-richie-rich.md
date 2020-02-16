---
layout: post
redirect_from:
  - /blog/2016/05/23/hackerrank-may-world-codesprint-richie-rich/
date: 2016-05-23T01:49:47+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint", "simulation" ]
"target_url": [ "https://www.hackerrank.com/contests/may-world-codesprint/challenges/richie-rich" ]
---

# HackerRank May World CodeSprint: Richie Rich

## problem

数字の列$S$と整数$K$が与えられる。
$S$の文字を高々$K$個置き換えてできる数字の列で回文であるものを考え、そのようなものの中で辞書順最小を答えよ。

## solution

Replace the unmatched digit by the other, greedily.  e.g. `173454121` to `173454371`.
After this, if another replacing is possible, then make `9` digits. like: `173454371` to `973454379`.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n, k; cin >> n >> k;
    string t; cin >> t;
    const string s = t; // original
    bool is_palindromic = true;
    repeat (i,n/2) if (t[i] != t[n-1-i]) {
        if (not k) {
            is_palindromic = false;
            break;
        } else {
            -- k;
            t[i] = t[n-1-i] = max(t[i], t[n-1-i]);
        }
    }
    repeat (i,n/2) {
        if (not k) break;
        if (t[i] == '9') continue;
        if (s[i] != s[n-1-i]) ++ k; // rewinding
        if (k >= 2) {
            -- k;
            -- k;
            t[i] = t[n-1-i] = '9';
        }
    }
    if (k and t[n/2] != '9') {
        -- k;
        t[n/2] = '9';
    }
    assert (k >= 0);
    cout << (is_palindromic ? t : "-1") << endl;
    return 0;
}
```
