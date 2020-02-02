---
layout: post
alias: "/blog/2016/06/12/jag2016-domestic2-b/"
title: "JAG 模擬国内予選 2016: B - jfen"
date: 2016-06-12T22:30:39+09:00
tags: [ "competitive", "writeup", "icpc", "jag" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2016%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8B" ]
---

コンテスト中に書いた。

## solution

与えられた通りに書く。$2 \le H,W \le 9$なので適当にやる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <cctype>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
vector<string> decode(string s) {
    vector<string> f;
    f.push_back("");
    for (char c : s) {
        if (c == '/') {
            f.push_back("");
        } else if (c == 'b') {
            f.back() += 'b';
        } else if (isdigit(c)) {
            repeat (i,c-'0') {
                f.back() += '.';
            }
        }
    }
    return f;
}
string encode(vector<string> const & f) {
    string s;
    repeat (y,f.size()) {
        if (y) s += '/';
        repeat (x,f[y].size()) {
            if (f[y][x] == 'b') {
                s += 'b';
            } else if (f[y][x] == '.') {
                if (not s.empty() and isdigit(s.back())) {
                    s.back() += 1;
                } else {
                    s += '1';
                }
            }
        }
    }
    return s;
}
int main() {
    while (true) {
        string s; cin >> s;
        if (s == "#") break;
        vector<string> f = decode(s);
        int a, b, c, d; cin >> a >> b >> c >> d; -- a; -- b; -- c; -- d;
        f[a][b] = '.';
        f[c][d] = 'b';
        string t = encode(f);
        cout << t << endl;
    }
    return 0;
}
```
