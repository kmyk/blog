---
layout: post
alias: "/blog/2017/12/29/utpc2011-i/"
date: "2017-12-29T07:48:16+09:00"
tags: [ "competitive", "writeup", "utpc", "aoj", "dp" ]
---

# 東京大学プログラミングコンテスト2011: I. ビット演算

-   <http://www.utpc.jp/2011/problems/bit.html>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2267>

## solution

bit数$K = \log \max x\_i$に対し$\mathrm{dp} : (K+1) \times 2^N \to \mathrm{String}$なDP。$O(K2^N)$。

それぞれの桁ごとに作ってbit和を取ればよい。
左右shiftや除算がないので、上位の桁の不一致を下位の桁の不一致へは運べない。
例えば$f(0) = 0; \; f(2) = 1$であるような関数は書けない。
よって下から$k$桁目については、$0, 1, \dots, k - 1$桁目を`((x*8)&16)`などとして取り出しこれらから構成できるものが全てである。
これは簡単なDPで求まる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

void check(int n, vector<uint32_t> const & x, vector<uint32_t> const & y) {
    auto distinguishable = vectors(n, n, bool());
    REP (k, 8) {
        REP (j, n) REP (i, j) if (i != j) {
            if ((x[i] & (1 << k)) != (x[j] & (1 << k))) {
                distinguishable[i][j] = true;
            }
            if ((y[i] & (1 << k)) != (y[j] & (1 << k))) {
                assert (distinguishable[i][j]);
            }
        }
    }
}

uint8_t kth_column(vector<uint32_t> const & x, int k) {
    int n = x.size();
    assert (n <= 8);
    uint8_t acc = 0;
    REP (i, n) {
        if (x[i] & (1 << k)) {
            acc |= 1 << i;
        }
    }
    return acc;
}

int main() {
    // input
    int n; cin >> n;
    vector<uint32_t> x(n), y(n);
    REP (i, n) cin >> x[i] >> y[i];
    // solve
    check(n, x, y);
    string result = "0";
    vector<string> memo(1 << n);
    memo[0] = "0";
    memo[(1 << n) - 1] = "1";
    REP (k, 8) {
        // prepare a queue
        queue<uint8_t> que;
        auto push = [&](uint8_t a, string const & s) {
            if (memo[a].empty()) {
                que.push(a);
                memo[a] = s;
            }
        };
        { // add a new primitive
            ostringstream oss;
            oss << "(x&" << (1 << k) << ")";
            push(kth_column(x, k), oss.str());
        }
        // breath first search
        while (not que.empty()) {
            uint8_t a = que.front(); que.pop();
            string s = memo[a];
            {
                ostringstream oss;
                oss << "((~" << s << ")&" << (1 << k) << ")";
                push((~ a) & ((1 << n) - 1), oss.str());
            }
            REP (b, 1 << n) if (not memo[b].empty()) {
                string t = memo[b];
                push(a & b, "(" + s + "&" + t + ")");
                push(a | b, "(" + s + "|" + t + ")");
                push(a ^ b, "(" + s + "^" + t + ")");
            }
        }
        // add to the result
        assert (not memo[kth_column(y, k)].empty());
        result = "(" + result + "|" + memo[kth_column(y, k)] + ")";
        // lshift old items
        REP (a, 1 << n) if (not memo[a].empty()) {
            memo[a] = "(" + memo[a] + "*2)";
        }
    }
    // output
    cout << result << endl;
    return 0;
}
```
