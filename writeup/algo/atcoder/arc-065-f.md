---
layout: post
title: "AtCoder Regular Contest 065: F - シャッフル / Shuffling"
date: 2018-09-25T01:10:19+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc065/tasks/arc065_d" ]
---

## 解法

### 概要

左端が単調なことから右端も単調にしてよい。
DP。
一見すると$3$乗に見えるがよく見ると$2$乗になってるやつ (典型)。
$O(NM)$。

### 詳細

右端は単調と仮定してよい。
そうでないとき、ある操作が直前の操作に包含されているのでその操作を取り除いて構わない。

$i$番目の操作まで見て、$[0, l _ {i + 1})$まで確定させ、$[l _ {i + 1}, r_i)$中に$1$が$a$個残っているような状態での、それまでに確定した部分でありえる文字列の数を$\mathrm{dp}(i, a)$とする。
右端が単調なので操作があったが未確定の範囲では、その中の$1$の数だけ覚えておけば十分だというのが重要。
$a \le r_i - l _ {i + 1}$であるので値が$0$でない引数の数は$N + M$個しかなく、計算量が落ちる。

## メモ

雰囲気でやればできた。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t value;  // faster than int32_t a little
    mint() = default;  // value is not initialized
    mint(int64_t value_) : value(value_) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->value - other.value; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->value -= other.value; if (this->value <    0) this->value += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->value ? MOD - this->value : 0); }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this, y = 1;
        for (; k; k >>= 1) {
            if (k & 1) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const { return pow(MOD - 2); }  // MOD must be a prime
};

template <int32_t MOD>
mint<MOD> fact(int n) {
    static vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}
template <int32_t PRIME>
mint<PRIME> inv_fact(int n) {
    static vector<mint<PRIME> > memo;
    if (memo.size() <= n) {
        int l = memo.size();
        int r = n * 1.3 + 100;
        memo.resize(r);
        memo[r - 1] = fact<PRIME>(r - 1).inv();
        for (int i = r - 2; i >= l; -- i) {
            memo[i] = memo[i + 1] * (i + 1);
        }
    }
    return memo[n];
}

template <int32_t MOD>
mint<MOD> choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) * inv_fact<MOD>(n - r) * inv_fact<MOD>(r);
}

constexpr int MOD = 1e9 + 7;
mint<MOD> solve(int n, int m, string const & s, vector<pair<int, int> > ops) {
    // remove included queries
    ops.erase(unique(ALL(ops), [&](auto a, auto b) {
        assert (a.first <= a.second);
        return a.second >= b.second;
    }), ops.end());
    m = ops.size();

    // cumulative sums of '1'
    vector<int> cnt(n + 1);
    REP (i, n) cnt[i + 1] += cnt[i] + (s[i] - '0');

    vector<mint<MOD> > cur(n + 1), prv;
    cur[0] = 1;
    REP (j, m) {
        int l, r; tie(l, r) = ops[j];
        cur.swap(prv);
        cur.assign(n + 1, 0);

        // previous
        int prev_r = (j == 0 ? 0 : ops[j - 1].second);
        if (prev_r < l) {
            prev_r = l;
            REP3 (a, 1, n + 1) assert (prv[a].value == 0);
        }

        // next
        int next_l = (j == m - 1 ? n : ops[j + 1].first);
        if (r < next_l) next_l = r;

        // fix [l, next_l)
        int a0 = cnt[r] - cnt[prev_r];
        int b0 = (r - prev_r) - a0;
        REP (a1, prev_r - l + 1) if (prv[a1].value) {
            int b1 = (prev_r - l) - a1;
            REP (a, next_l - l + 1) {
                int b = (next_l - l) - a;
                if (a <= a0 + a1 and b <= b0 + b1) {
                    cur[a0 + a1 - a] += prv[a1] * choose<MOD>(a + b, a);
                }
            }
        }
    }

    REP3 (a, 1, n + 1) assert (cur[a].value == 0);
    return cur[0];
}

int main() {
    int n, m; cin >> n >> m;
    string s; cin >> s;
    vector<pair<int, int> > ops(m);
    REP (j, m) {
        int l, r; cin >> l >> r;
        -- l;
        ops[j] = { l, r };
    }
    cout << solve(n, m, s, ops).value << endl;
    return 0;
}
```
