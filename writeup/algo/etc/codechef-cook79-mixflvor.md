---
layout: post
alias: "/blog/2018/04/05/codechef-cook79-mixflvor/"
title: "CodeChef Cook79: E. Mixing flavors"
date: "2018-04-05T07:02:02+09:00"
tags: [ "competitive", "writeup", "codechef", "square-root-decomposition", "two-pointers", "mo-algorithm", "xor", "gaussian-elimination" ]
"target_url": [ "https://www.codechef.com/COOK79/problems/MIXFLVOR" ]
---

## problem

アイスクリームが$N$種類売っている。
それぞれ$C\_i$円で$F\_i$味である。
予算の$K$円に収まるように連続する区間をひとつ決め、その範囲中のアイスクリームを全て買い、買ったなかからいくつか選んで味を混ぜ合わせることができる。
味$x, y$のアイスクリームを混ぜると味$x \oplus y$となる。
食べることのできるアイスクリームの最も大きな味はいくつか。

## solution

[rollback平方分割](http://snuke.hatenablog.com/entry/2016/07/01/000000)。
計算量は$O(N + Q \sqrt{N} \log F\_i)$ぐらい、ただし$Q$は試すべき区間の数。

お金を余らせても仕方がないので、左端を決めたら右端は伸ばせるだけ伸ばしてよい。
そうして得られた区間のそれぞれについて、その中のアイスクリームを混ぜた場合の最大の味を計算したい。
区間が固定されれば、味を$\mathbb{F}\_2$上のvectorと見てGaussの消去法で基底を求めその総和が最大の味。
基底からvectorを除去するのは難しいため、平方分割を用いてやれば通る。

## note

-   [editorial](https://discuss.codechef.com/questions/91508/mixflvor-editorial)はstackふたつ持ってqueueにしていい感じにやるって言ってる

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

/**
 * @brief the extended Mo's algorithm
 * @arg stupid is called O(Q) times, each length is O(\sqrt{N})
 * @arg mo si the following:
 *     struct rollback_mo_interface {
 *         void reset(int l);  // called O(N) times
 *         void extend_left( int l, int r);  // called O(Q) times, the sum of length is O(N \sqrt {N})
 *         void extend_right(int l, int r);  // called O(Q) times, the sum of length is O(Q \sqrt {N})
 *         void snapshot();  // called O(Q) times
 *         void rollback();  // called O(Q) times
 *         void query();     // called O(Q) times
 *     };
 * @see http://snuke.hatenablog.com/entry/2016/07/01/000000
 * @see http://codeforces.com/blog/entry/7383?#comment-161520
 */
template <class Func, class RollbackMoInterface>
void rollback_square_decomposition(int n, vector<pair<int, int> > const & range, RollbackMoInterface & mo, Func stupid) {
    int bucket_size = sqrt(n);
    int bucket_count = (n + bucket_size - 1) / bucket_size;
    vector<vector<int> > bucket(bucket_count);
    REP (i, int(range.size())) {
        int l, r; tie(l, r) = range[i];
        if (r - l <= bucket_size) {
            stupid(l, r);
        } else {
            bucket[l / bucket_size].push_back(i);
        }
    }
    REP (b, bucket_count) {
        sort(ALL(bucket[b]), [&](int i, int j) { return range[i].second < range[j].second; });
        int l = (b + 1) * bucket_size;
        mo.reset(l);
        int r = l;
        for (int i : bucket[b]) {
            int l_i, r_i; tie(l_i, r_i) = range[i];
            mo.extend_right(r, r_i);
            mo.snapshot();
            mo.extend_left(l_i, l);
            mo.query();
            mo.rollback();
            r = r_i;
        }
    }
}

uint32_t msb(uint32_t x) {
    return 1u << (31 - __builtin_clz(x));
}
struct basis_t {
    vector<uint32_t> data;
    void add_vector(uint32_t x) {
        for (uint32_t y : data) {
            if (x & msb(y)) x ^= y;
        }
        if (x == 0) return;
        for (uint32_t & y : data) {
            if (y & msb(x)) y ^= x;
        }
        data.push_back(x);
    }
    uint32_t get() {
        return accumulate(ALL(data), 0, bit_xor<uint32_t>());
    }
    void clear() {
        data.clear();
    }
};

struct rollback_mo_interface {
    vector<uint32_t> f;
    basis_t basis;
    stack<basis_t> history;
    uint32_t answer;
    rollback_mo_interface(vector<uint32_t> const & f)
            : f(f)
            , answer(0) {
    }

    // rollback_square_decomposition
    void reset(int l) {
        basis.clear();
    }
    void extend_left(int l, int r) {
        REP3 (i, l, r) basis.add_vector(f[i]);
    }
    void extend_right(int l, int r) {
        REP3 (i, l, r) basis.add_vector(f[i]);
    }
    void snapshot() {
        history.push(basis);
    }
    void rollback() {
        basis = history.top();
        history.pop();
    }
    void query() {
        chmax(answer, basis.get());
    }
};
int solve(int n, ll k, vector<int> const & c, vector<uint32_t> const & f) {
    vector<pair<int, int> > range; {
        int l = 0, r = 0;
        ll sum_c = 0;
        while (l < n) {
            if (r < l) {
                r = l;
                sum_c = 0;
            }
            while (r < n and sum_c + c[r] <= k) {
                sum_c += c[r];
                ++ r;
            }
            if (l < r) {
                if (range.empty() or range.back().second < r) {
                    range.emplace_back(l, r);
                }
            }
            sum_c -= c[l];
            ++ l;
        }
    }
    uint32_t answer = 0;
    auto stupid = [&](int l, int r) {
        basis_t basis;
        REP3 (i, l, r) {
            basis.add_vector(f[i]);
        }
        chmax(answer, basis.get());
    };
    rollback_mo_interface mo(f);
    rollback_square_decomposition(n, range, mo, stupid);
    chmax(answer, mo.answer);
    return answer;
}

int main() {
    int t; cin >> t;
    while (t --) {
        int n; ll k; cin >> n >> k;
        vector<int> c(n);
        vector<uint32_t> f(n);
        REP (i, n) cin >> c[i] >> f[i];
        int result = solve(n, k, c, f);
        cout << result << endl;
    }
    return 0;
}
```
