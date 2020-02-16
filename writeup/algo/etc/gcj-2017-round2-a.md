---
layout: post
alias: "/blog/2017/05/14/gcj-2017-round2-a/"
date: "2017-05-14T01:55:06+09:00"
tags: [ "competitive", "writeup", "gcj", "dp" ]
"target_url": [ "https://code.google.com/codejam/contest/5314486/dashboard#s=p0" ]
---

# Google Code Jam 2017 Round 2: A. Fresh Chocolate

## problem

整数$2 \le P \le 4$、長さ$N \le 100$の正整数の列$G$が与えられる。
$G$を適当に並び変えて、$k$項目までの累積和$\sum\_{i \le k} G\_i$が$P$で割り切れるような$k$の数を最大化し、その数を答えよ。

## solution

動的計画法。メモ化再帰で実装して間に合う。$O(N^P)$。

## implementation

汚ない。
どうせ汚ないのでtemplateの除去とかもしてないまま貼っておく。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <array>
#include <numeric>
#include <set>
#include <map>
#include <queue>
#include <tuple>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= int(m); --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
#define debug(x) #x << " = " << (x) << " "
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

bool is_valid(array<int, 4> const & a) {
    return a[0] >= 0 and a[1] >= 0 and a[2] >= 0 and a[3] >= 0;
}
int func(array<int, 4> const & a) {
    static map<array<int, 4>, int> memo;
    if (not memo.count(a)) {
        if (whole(accumulate, a, 0) == 0) {
            memo[a] = 0;
        } else {
            int result = 1;
            {
                array<int, 4> b = a;
                b[1] -= 1;
                b[3] -= 1;
                if (is_valid(b)) setmax(result, func(b) + 1);
            }
            {
                array<int, 4> b = a;
                b[2] -= 2;
                if (is_valid(b)) setmax(result, func(b) + 1);
            }
            {
                array<int, 4> b = a;
                b[1] -= 4;
                if (is_valid(b)) setmax(result, func(b) + 1);
            }
            {
                array<int, 4> b = a;
                b[3] -= 4;
                if (is_valid(b)) setmax(result, func(b) + 1);
            }
            {
                array<int, 4> b = a;
                b[1] -= 2;
                b[2] -= 1;
                if (is_valid(b)) setmax(result, func(b) + 1);
            }
            {
                array<int, 4> b = a;
                b[3] -= 2;
                b[2] -= 1;
                if (is_valid(b)) setmax(result, func(b) + 1);
            }
            memo[a] = result;
        }
    }
    return memo[a];
}
int solve(int p, vector<int> const & g) {
    vector<int> cnt(p);
    for (int gi : g) cnt[gi % p] += 1;
    if (p == 2) {
        return cnt[0] + (cnt[1] + 1) / 2;
    } else if (p == 3) {
        int result = 0;
        result += cnt[0];
        cnt[0] = 0;
        int delta = min(cnt[1], cnt[2]);
        result += delta;
        cnt[1] -= delta;
        cnt[2] -= delta;
        result += cnt[1] / 3;
        cnt[1] %= 3;
        result += cnt[2] / 3;
        cnt[2] %= 3;
        if (cnt[1]) {
            result += 1;
            cnt[1] -= 1;
        } else if (cnt[2]) {
            result += 1;
            cnt[2] -= 1;
        }
        return result;
    } else if (p == 4) {
        int result = 0;
        result += cnt[0];
        cnt[0] = 0;
        array<int, 4> a;
        repeat (i, 4) a[i] = cnt[i];
        result += func(a);
        return result;
    } else {
        assert (false);
    }
}

int main() {
    int t; scanf("%d", &t);
    repeat (x,t) {
        int n, p; scanf("%d%d", &n, &p);
        vector<int> g(n); repeat (i,n) scanf("%d", &g[i]);
        int result = solve(p, g);
        printf("Case #%d: %d\n", x+1, result);
    }
    return 0;
}
```
