---
layout: post
redirect_from:
  - /blog/2017/12/25/utpc2011-c/
date: "2017-12-25T19:10:40+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj" ]
---

# 東京大学プログラミングコンテスト2011: C. [[iwi]]

-   <http://www.utpc.jp/2011/problems/iwi2.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_3>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2261>

## solution

全ての部分列について試す。$O(N2^N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

bool pred(string const & t) {
    int n = t.length();
    if (n % 2 == 0) return false;
    if (n < 3) return false;
    if (t[n / 2 - 1] != 'i') return false;
    if (t[n / 2    ] != 'w') return false;
    if (t[n / 2 + 1] != 'i') return false;
    REP (i, n / 2 - 1) {
        char c;
        switch (t[i]) {
            case '(': c = ')'; break;
            case ')': c = '('; break;
            case '[': c = ']'; break;
            case ']': c = '['; break;
            case '{': c = '}'; break;
            case '}': c = '{'; break;
            default: return false;
        }
        if (c != t[n - i - 1]) return false;
    }
    return true;
}

int main() {
    string s; cin >> s;
    int result = 0;
    REP (x, 1 << s.length()) {
        string t;
        REP (i, s.length()) if (x & (1 << i)) {
            t += s[i];
        }
        if (pred(t)) {
            chmax<int>(result, t.length());
        }
    }
    cout << result << endl;
    return 0;
}
```
