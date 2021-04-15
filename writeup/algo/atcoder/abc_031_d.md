---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_031_d/
  - /writeup/algo/atcoder/abc-031-d/
  - /blog/2015/11/21/abc-031-d/
date: 2015-11-21T23:09:47+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
---

# AtCoder Beginner Contest 031 D - 語呂合わせ

やるだけなので解法面では何もないですが、題材と問題の仕方は好きです。

<!-- more -->

## [D - 語呂合わせ](https://beta.atcoder.jp/contests/abc031/tasks/abc031_d) {#d}

### 解法

それぞれの数字について$s_i$の長さだけ決めればよい。
$1 \le |s_i| \le 3$であるので、探索空間は$3^9$と小さい。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
bool solve(int y, int xv, int xw, vector<string> const & v, vector<string> const & w, map<int,string> & s) {
    if (y == v.size()) return true;
    if (xv == v[y].size() and xw == w[y].size()) return solve(y+1, 0, 0, v, w, s);
    if (xv == v[y].size()  or xw == w[y].size()) return false;
    int n = v[y][xv] - '0';
    if (s.count(n)) {
        string t = s[n];
        if (w[y].substr(xw, t.length()) == t) {
            return solve(y, xv+1, xw+t.length(), v, w, s);
        } else {
            return false;
        }
    } else {
        repeat_from (l,1,3+1) {
            string t = w[y].substr(xw, l);
            if (t.length() != l) break;
            s[n] = t;
            if (solve(y, xv+1, xw+l, v, w, s)) return true;
        }
        s.erase(n);
    }
    return false;
}
int main() {
    int k, n; cin >> k >> n;
    vector<string> v(n), w(n); repeat (i,n) cin >> v[i] >> w[i];
    map<int,string> s;
    solve(0, 0, 0, v, w, s);
    repeat (i,k) cout << s[i+1] << endl;
    return 0;
}
```
