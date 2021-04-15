---
layout: post
redirect_from:
  - /writeup/algo/atcoder/kupc-2013-b/
  - /blog/2017/05/12/kupc-2013-b/
date: "2017-05-12T20:28:47+09:00"
tags: [ "competitive", "writeup", "atcoder", "kupc" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2013/tasks/kupc2013_b" ]
---

# 京都大学プログラミングコンテスト2013: B - ライオン

## solution

全列挙。$O(x^nnm)$あるいは$O(x^n(n + m))$。

## implementation

Bにしては面倒じゃない？

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <array>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    // input
    int n, x, m; scanf("%d%d%d", &n, &x, &m);
    vector<int> l(m), r(m), s(m);
    repeat (i,m) {
        scanf("%d%d%d", &l[i], &r[i], &s[i]);
        -- l[i];
    }
    // compute
    constexpr int max_n = 6;
    assert (n <= max_n);
    array<int, max_n> result;
    int sum_result = -1;
    int pow_x_n = pow(x+1, n);
    repeat (counter, pow_x_n) {
        array<int, max_n> a = {}; {
            int acc = counter;
            repeat (i,max_n) {
                a[i] = acc % (x+1);
                acc /= x+1;
            }
        }
        bool is_valid = true;
        repeat (i,m) {
            int acc = accumulate(a.begin() + l[i], a.begin() + r[i], 0);
            if (acc != s[i]) {
                is_valid = false;
                break;
            }
        }
        if (is_valid) {
            int acc = whole(accumulate, a, 0);
            if (sum_result < acc) {
                sum_result = acc;
                result = a;
            }
        }
    }
    // output
    if (sum_result == -1) {
        printf("%d\n", -1);
    } else {
        repeat (i,n) {
            printf("%d%c", result[i], i < n-1 ? ' ' : '\n');
        }
    }
    return 0;
}
```
