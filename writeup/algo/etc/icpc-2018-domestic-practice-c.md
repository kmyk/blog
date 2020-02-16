---
layout: post
date: 2018-07-01T23:59:02+09:00
tags: [ "competitive", "writeup", "icpc-domestic" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2018%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88" ]
---

# ACM-ICPC 2018 模擬国内予選: C. 知識の証明

## 解法

再帰下降構文解析やるだけ。

逆から読めばRPNになってstackひとつで済む(たぶん典型)は気付かなかったが頭いい。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

int eval(const char **s, array<int, 4> const & p) {
    if (**s == '[') {
        ++ *s;
        char op = *((*s) ++);
        int a = eval(s, p);
        int b = eval(s, p);
        assert (**s == ']');
        ++ *s;
        if (op == '+') {
            return a | b;
        } else if (op == '*') {
            return a & b;
        } else if (op == '^') {
            return a ^ b;
        } else {
            assert (false);
        }
    } else {
        assert ('a' <= **s and **s <= 'd');
        return p[*((*s) ++) - 'a'];
    }
}

int eval(string const & s, int p) {
    const char *ptr = s.c_str();
    array<int, 4> ary;
    REP_R (i, 4) {
        ary[i] = p % 10;
        p /= 10;
    }
    return eval(&ptr, ary);
}

int main() {
    while (true) {
        // input
        string s; cin >> s;
        if (s == ".") break;
        int p; cin >> p;

        // solve
        int hash = eval(s, p);
        int cnt = 0;
        REP (q, 10000) {
            cnt += eval(s, q) == hash;
        }

        // output
        cout << hash << ' ' << cnt << endl;
    }
    return 0;
}
```
