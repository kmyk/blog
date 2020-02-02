---
layout: post
alias: "/blog/2018/01/05/arc-069-e/"
title: "AtCoder Regular Contest 069: E - Frequency"
date: "2018-01-05T23:34:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "wavelet-matrix" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc069/tasks/arc069_c" ]
---

非想定解。
Wavelet木、最高。

## solution

Wavelet木で殴る。
$O(N \log a\_{\mathrm{max}})$。

$O(N \sum a\_i)$の愚直解を考えよう。
最も大きい要素 (複数あるなら最も手前)を$a\_j$、それより手前で最も大きい要素を$a\_i$とする。
$a\_j$より真に後ろで$a\_i$より大きい要素をちょうど$a\_i$まで全て削り、その後に$a\_j$を$a\_i$まで削っていくような動きが最適。
これを効率良く処理したい。
Wavelet木を用いて区間$[l, r)$中で値が範囲$[a, b)$の中な要素をひとつあたり$O(\log a\_{\mathrm{max}})$で列挙すれば、効率良く処理できる。
全体では$O(N \log a\_{\mathrm{max}})$。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <climits>
#include <cstdio>
#include <numeric>
#include <stack>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

/**
 * @brief a fully indexable dictionary
 * @note space complexity o(N). 1.5N-bit consumed
 */
class fully_indexable_dictionary {
    static constexpr size_t block_size = 64;
    vector<uint64_t> block;
    vector<int32_t> rank_block;  // a blocked cumulative sum
public:
    size_t size;
    fully_indexable_dictionary() = default;
    template <typename T>
    fully_indexable_dictionary(vector<T> const & bits) {
        size = bits.size();
        size_t block_count = size / block_size + 1;
        block.resize(block_count);
        REP (i, size) if (bits[i]) {
            block[i / block_size] |= (1ull << (i % block_size));
        }
        rank_block.resize(block_count);
        rank_block[0] = 0;
        REP (i, block_count - 1) {
            rank_block[i + 1] = rank_block[i] + __builtin_popcountll(block[i]);
        }
    }
    /**
     * @brief count the number of value in [0, r)
     * @note O(1)
     */
    int rank(bool value, int r) const {
        assert (0 <= r and r <= size);
        uint64_t mask = (1ull << (r % block_size)) - 1;
        int rank_1 = rank_block[r / block_size] + __builtin_popcountll(block[r /block_size] & mask);
        return value ? rank_1 : r - rank_1;
    }
    int rank(bool value, int l, int r) const {
        assert (0 <= l and l <= r and r <= size);
        return rank(value, r) - rank(value, l);
    }
};

/**
 * @brief a wavelet matrix
 * @tparam BITS express the range [0, 2^BITS) of values. You can assume BITS \le \log N, using coordinate compression
 */
template <int BITS>
struct wavelet_matrix {
    static_assert (BITS < CHAR_BIT * sizeof(uint64_t), "");
    array<fully_indexable_dictionary, BITS> fid;
    array<int, BITS> zero_count;
    wavelet_matrix() = default;
    /**
     * @note O(N BITS)
     */
    template <typename T>
    wavelet_matrix(vector<T> data) {
        int size = data.size();
        REP (i, size) {
            assert (0 <= data[i] and data[i] < (1ull << BITS));
        }
        // bit-inversed radix sort
        vector<char> bits(size);
        vector<T> next(size);
        REP_R (k, BITS) {
            auto low  = next.begin();
            auto high = next.rbegin();
            REP (i, size) {
                bits[i] = bool(data[i] & (1ull << k));
                (bits[i] ? *(high ++) : *(low ++)) = data[i];
            }
            fid[k] = fully_indexable_dictionary(bits);
            zero_count[k] = low - next.begin();
            reverse(next.rbegin(), high);
            data.swap(next);
        }
    }
    /**
     * @brief flexible version of range_frequency
     * @note O(K BITS), K is the number of kinds of values in the range
     * @arg void callback(uint64_t value, int count)
     */
    template <typename Func>
    void range_frequency_callback(int l, int r, uint64_t value_l, uint64_t value_r, Func callback) const {
        assert (0 <= l and l <= r and r <= fid[0].size);
        assert (0 <= value_l and value_l <= value_r and value_r <= (1ull << BITS));
        range_frequency_callback(BITS - 1, l, r, 0, value_l, value_r, callback);
    }
    template <typename Func>
    void range_frequency_callback(int k, int l, int r, uint64_t v, uint64_t a, uint64_t b, Func callback) const {
        if (l == r) return;
        if (b <= v) return;
        if (k == -1) {
            if (a <= v) callback(v, r - l);
            return;
        }
        uint64_t nv  = v  | (1ull << k);
        uint64_t nnv = nv | (((1ull << k) - 1));
        if (nnv < a) return;
        int lc = fid[k].rank(1, l);
        int rc = fid[k].rank(1, r);
        range_frequency_callback(k - 1,             l - lc,             r - rc,  v, a, b, callback);
        range_frequency_callback(k - 1, lc + zero_count[k], rc + zero_count[k], nv, a, b, callback);
    }
};

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); REP (i, n) scanf("%d", &a[i]);
    // solve
    stack<int> stk;
    REP (i, n) {
        if (stk.empty() or a[stk.top()] < a[i]) {
            stk.push(i);
        }
    }
    vector<ll> result(n);
    wavelet_matrix<32> wm(a);
    int j = stk.top(); stk.pop();
    int saturated = 0;
    wm.range_frequency_callback(j, n, a[j], INT_MAX, [&](uint64_t value, int count) {
        saturated += count;
    });
    while (not stk.empty()) {
        int i = stk.top(); stk.pop();
        result[j] += (a[j] - a[i]) *(ll) saturated;
        wm.range_frequency_callback(i, n, a[i], a[j], [&](uint64_t value, int count) {
            saturated += count;
            result[j] += (value - a[i]) * count;
        });
        j = i;
    }
    result[0] = accumulate(ALL(a), 0ll) - accumulate(ALL(result), 0ll);
    // output
    REP (i, n) {
        printf("%lld\n", result[i]);
    }
    return 0;
}
```
