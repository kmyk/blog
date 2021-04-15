---
layout: post
redirect_from:
  - /writeup/algo/codeforces/356-a/
  - /blog/2016/03/31/cf-356-a/
date: 2016-03-31T23:21:57+09:00
tags: [ "competitive", "writeup", "codeforces" ]
"target_url": [ "http://codeforces.com/contest/356/problem/A" ]
---

# Codeforces Round #207 (Div. 1) A. Knight Tournament

## 問題

配列がある。
以下のクエリを順次処理し、結果の配列を出力せよ。

-   区間$[l, r]$中の$x$番目以外の要素で、まだ代入がなされていない要素に関し、$x$を代入する。

## 解法

skip量配列を横に持つ。$O(N)$。

連続した区間がまとめて処理されるので、そこを飛ばしたい。
各位置に関して、次の未代入の要素の位置を持って、これを適当に更新しながら処理する。

## 実装

``` c++
#include <iostream>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<int> a(n);
    vector<int> skip(n); repeat (i,n) skip[i] = i+1;
    function<int (int,int,int)> rec = [&](int l, int r, int x) {
        if (r <= l) return r;
        if (not a[l]) a[l] = x;
        return skip[l] = rec(skip[l], r, x);
    };
    repeat (query,m) {
        int l, r, x; cin >> l >> r >> x; -- l; -- x;
        rec(l,   x, x+1);
        rec(x+1, r, x+1);
    }
    repeat (i,n) { if (i) cout << ' '; cout << a[i]; } cout << endl;
    return 0;
}
```
