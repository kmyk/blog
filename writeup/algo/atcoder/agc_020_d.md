---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-020-d/
  - /blog/2018/02/25/agc-020-d/
date: "2018-02-25T05:31:19+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "construction", "string" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc020/tasks/agc020_d" ]
---

# AtCoder Grand Contest 020: D - Min Max Repetition

時間をかければ解けるけどコンテスト中では間に合わないやつ。
なんとなく構成はできてしまったが証明が書けるほどの理解はしてない (ので解説も曖昧)。

## solution

頑張って観察。繰り返しの回数を二分探索でいい感じにやる。$O(\log (A + B) + (D - C))$。

$f(A, B)$の部分文字列であって同じ文字からなるもののうち最長のものの長さを$k$とする。
この$k$は$O(1)$で求まる。
文字列$f(A, B)$はだいたい$\underbrace{AAA\dots A}\_{k}B\underbrace{AAA\dots A}\_{k}B\dots\underbrace{AAA\dots A}\_{k}B???\dots ?A\underbrace{BBB\dots B}\_{k}A\underbrace{BBB\dots B}\_{k}\dots A\underbrace{BBB\dots B}\_{k}$のような形となる。

$A \ge B$と仮定してよい。
先頭に$\underbrace{AAA\dots A}\_{k}$が来るのは確定 ($k$の最小性と$A \ge B$)。
続く前半部分の$B\underbrace{AAA\dots A}\_{k}$が繰り返される回数は、そのように使ったとしても$k$を変えない最大の値として二分探索で求まる。
これを固定し、後半部分においても同様に繰り返される回数を二分探索。
いい感じに中央部分を処理して繋ぐ。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch_max(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    ++ r;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? l : r) = m;
    }
    return l;
}

int get_k(int a, int b) {
    if (a < b) swap(a, b);
    return (a + (b + 1) - 1) / (b + 1);
}

string generate(int a, int b, int l, int r, int k) {
    assert (a >= 0 and b >= 0);
    assert (0 <= l and l <= r and r <= a + b);
    if (a < b) {
        string s = generate(b, a, a + b - r, a + b - l, k);
        reverse(ALL(s));
        for (char & c : s) c ^= 'a' ^ 'b';
        return s;
    }
    assert (a >= b);
    if (a < k) {
        string s;
        REP3 (i, l, r) {
            s += i < a ? 'A' : 'B';
        }
        return s;
    }
    int x = binsearch_max(0, a + b, [&](int x) {
        int na = a - k - k * x;
        int nb = b - x;
        return na >= 0 and nb >= 0 and get_k(na, nb) <= k;
    });
    string s;
    REP3 (i, l, r) {
        if (i < k) {
            s += 'A';
        } else if (i < k + (1 + k) * x) {
            s += (i - k) % (1 + k) ? 'A' : 'B';
        }
    }
    int na = a - k - k * x;
    int nb = b - x;
    if (nb == 0) assert (na == 0);
    if (nb >= 1) {
        nb -= 1;
        if (l <= k + (1 + k) * x and k + (1 + k) * x < r) {
            s += 'B';
        }
        int offset = k + (1 + k) * x + 1;
        s += generate(na, nb, max(0, l - offset), max(0, r - offset), k);
    }
    return s;
}
string generate(int a, int b, int l, int r) {
    int k = get_k(a, b);
    return generate(a, b, l, r, k);
}

int main() {
    int q; cin >> q;
    while (q --) {
        int a, b, c, d; cin >> a >> b >> c >> d;
        cout << generate(a, b, c - 1, d) << endl;
    }
    return 0;
}
```
