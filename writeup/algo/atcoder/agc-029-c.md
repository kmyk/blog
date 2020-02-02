---
layout: post
title: "AtCoder Grand Contest 029: C - Lexicographic constraints"
date: 2018-12-16T04:23:18+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "binary-search", "sequence", "run-length" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc029/tasks/agc029_c" ]
---

## 解法

### 概要

答え $$k$$ で二分探索。
$$k$$ が定まっているときは貪欲。
愚直に貪欲をすると間に合わないので文字列をrun-length圧縮のようにして持つ。
$$O(N (\log N)^2)$$。

### 詳細

文字種 $$k$$ が定まっているとする。
本当に $$k$$ 種類で足りているか判定したい。
このとき $$S_i$$ を前から順にそれ以前と整合する最小の文字列とし、これが構成できるか試せばよい。
具体的には、始めの文字列は $$S_1 = \underbrace{aaa \dots a} _ {A_1}$$。
$$A_i \lt A _ {i+1}$$ のとき $$S _ {i + 1} = S_i \underbrace{aaa \dots a} _ {A _ {i+1} - A_i}$$。
$$A_i \ge A _ {i+1}$$ のとき $$S _ {i + 1}$$ は $$S_i$$ を長さ $$A _ {i+1}$$ に制限したものよりひとつ大きい文字列。
これはインクリメントを実装する。
ここで $$S_i = zzz \dots z$$ のようなときはインクリメント先が存在せず、文字種 $$k$$ では足りなかったということになる。

愚直に実装すると間に合わない。
run-length圧縮のようにして持つか、末尾付近の必要な部分のみを連想配列で持つとよい。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;
        (p(m) ? r : l) = m;
    }
    return r;
}

void normalize_tail(vector<pair<int, int> > & s) {
    while (true) {
        bool modified = false;
        if (s.size() >= 1 and s.back().second == 0) {
            s.pop_back();
            modified = true;
        }
        if (s.size() >= 2 and s[s.size() - 2].first == s[s.size() - 1].first) {
            int k = s.back().second;
            s.pop_back();
            s.back().second += k;
            modified = true;
        }
        if (not modified) break;
    }
}

int try_increment(int k, vector<pair<int, int> > & s, int length) {
    if (s.back().first == k - 1) {
        length -= s.back().second;
        s.pop_back();
        if (s.empty()) {
            return 0;
        }
    }
    int c = s.back().first;
    assert (c + 1 < k);
    s.back().second -= 1;
    normalize_tail(s);
    s.emplace_back(c + 1, 1);
    normalize_tail(s);
    return length;
}

int solve(int n, vector<int> const & a) {
    return binsearch(1, n + 1, [&](int k) {
        vector<pair<int, int> > s;
        s.emplace_back(0, a[0]);  // "000...0"
        REP (i, n - 1) {
            if (a[i] < a[i + 1]) {
                s.emplace_back(0, a[i + 1] - a[i]);
                normalize_tail(s);
            } else {
                int length = a[i];
                while (length > a[i + 1]) {
                    int delta = min(s.back().second, length - a[i + 1]);
                    s.back().second -= delta;
                    length -= delta;
                    normalize_tail(s);
                }
                length = try_increment(k, s, length);
                if (not length) {
                    return false;
                }
                assert (not s.empty());
                if (length < a[i + 1]) {
                    s.emplace_back(0, a[i + 1] - length);
                    normalize_tail(s);
                }
            }
        }
        return true;
    });
}

int main() {
    int n; cin >> n;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, a) << endl;
    return 0;
}
```
