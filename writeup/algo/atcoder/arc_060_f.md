---
layout: post
date: 2018-08-21T01:27:17+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "string", "rolling-hash" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc060/tasks/arc060_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-060-f/
---

# AtCoder Regular Contest 060: F - 最良表現 / Best Representation

## solution

$w$ が単一の文字からなる場合を除いて $m \le 3$ であることを信じ、 rolling hash をEratosthenesの篩のようにして使った $O(|w|^2 \log |w|)$ がTLEしないことを祈りながら提出するとACする。
サンプルが変に弱いことやGoldbachの予想とその系からの類推が根拠となる。

## note

解説になってない。あと $|w| \le 5 \times 10^5$ の $O(|w|^2 \log |w|)$ は信じてもかなり厳しい気がする。

実際は$m \le 2$が証明できたようだ。
「悪い文字列の長さを$1$減らせば良い文字列になる」という主張が重要。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

constexpr uint64_t prime = 1000000009;
constexpr uint64_t base = 10007;
uint64_t rolling_hash_push(uint64_t hash, char c) {
    return (hash * base + c) % prime;
}
uint64_t rolling_hash_shift(uint64_t hash, uint64_t k) {
    uint64_t e = base;
    for (; k; k >>= 1) {
        if (k & 1) hash = hash * e % prime;
        e = e * e % prime;
    }
    return hash;
}
template <class Iterator>
vector<uint64_t> rolling_hash_prepare(Iterator first, Iterator last) {
    vector<uint64_t> hash(last - first + 1);
    REP (i, last - first) {
        hash[i + 1] = rolling_hash_push(hash[i], *(first + i));
    }
    return hash;
}

template <class Iterator>
vector<bool> make_is_good_array(Iterator first, Iterator last) {
    int n = last - first;
    auto hash = rolling_hash_prepare(first, last);
    vector<bool> p(n + 1, true);
    uint64_t h = 0;
    uint64_t shift = 1;
    REP3 (l, 1, n + 1) {
        h = rolling_hash_push(h, *(first + l - 1));
        shift = rolling_hash_push(shift, 0);
        uint64_t h1 = h;
        for (int r = 2 * l; r <= n; r += l) {
            h1 = (h1 * shift + h) % prime;
            if (h1 != hash[r]) break;
            p[r] = false;
        }
    }
    return p;
}

pair<int, int> solve(string const & w) {
    int n = w.length();
    if (count(ALL(w), w[0]) == n) {
        return make_pair(n, 1);  // w has only one letter
    }

    // m = 1
    auto is_good = make_is_good_array(ALL(w));
    if (is_good[n]) {
        return make_pair(1, 1);
    }

    // m = 2
    auto is_good_rev = make_is_good_array(w.rbegin(), w.rend());
    int cnt = 0;
    REP3 (i, 1, n) {
        cnt += is_good[i] and is_good_rev[n - i];
    }
    if (cnt) {
        return make_pair(2, cnt);
    }

    // m = 3
    REP3 (i, 1, n) if (is_good[i]) {
        auto is_good_shifted = make_is_good_array(w.begin() + i, w.end());  // :pray:
        REP (j, n - i) {
            cnt += is_good_shifted[j] and is_good_rev[n - j];
        }
    }
    assert (cnt);  // :pray:
    return make_pair(3, cnt);
}

int main() {
    string w; cin >> w;
    int m, cnt; tie(m, cnt) = solve(w);
    cout << m << endl;
    cout << cnt << endl;
    return 0;
}
```
