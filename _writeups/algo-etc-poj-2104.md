---
layout: post
redirect_from:
  - /writeup/algo/etc/poj-2104/
  - /blog/2017/12/27/poj-2104/
date: "2017-12-27T06:49:34+09:00"
tags: [ "competitive", "writeup", "poj", "wavelet-matrix" ]
"target_url": [ "http://poj.org/problem?id=2104" ]
---

# POJ 2104. K-th Number

UTPCの問題で `東京大学時代の自分が愛した問題「K 番目の数字」を...` という形で言及されていたので解いた。
結果は $14$CE $7$RE $8$WA $1$AC。埋めたバグはふたつあって、ひとつは普通のoff-by-one、もうひとつはPOJなので`vector<uint64_t>`は遅かろうと思って`uint64_t []`にしたら初期化が消えたことによるもの。POJは本当に楽しいオンラインジャッジですね。

## problem

長さ$N \le 10^5$の数列$A$が固定される。次のクエリが$Q \le 5000$個与えられるので処理せよ。

-   区間$[l, r)$と整数$k$が与えられる。数列$A$のその区間の中で$k$番目に小さい数を答えよ。

## solution

Wavelet行列を書くだけ。$O(M \log N)$。

なお蟻本には平方分割の例題として載っている。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <climits>
#include <cstdio>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
#define uint64_t unsigned long long
#define int32_t int
int popcountll(uint64_t r) {
    r = (r & 0x5555555555555555ULL) + ((r >> 1) & 0x5555555555555555ULL);
    r = (r & 0x3333333333333333ULL) + ((r >> 2) & 0x3333333333333333ULL);
    r = (r + (r >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
    r = r + (r >> 8);
    r = r + (r >> 16);
    r = r + (r >> 32);
    return r & 0x7f;
}
#define __builtin_popcountll popcountll
using namespace std;


class fully_indexable_dictionary {
    static const size_t block_size = 64;
    vector<uint64_t> block;
    vector<int32_t> rank_block;  // a blocked cumulative sum
public:
    size_t size;
    fully_indexable_dictionary() {}
    template <typename T>
    fully_indexable_dictionary(vector<T> const & bits) {
        size = bits.size();
        int block_count = size / block_size + 1;
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
    int rank(bool value, int r) const {
        uint64_t mask = (1ull << (r % block_size)) - 1;
        int rank_1 = rank_block[r / block_size] + __builtin_popcountll(block[r /block_size] & mask);
        return value ? rank_1 : r - rank_1;
    }
    int rank(bool value, int l, int r) const {
        return rank(value, r) - rank(value, l);
    }
};

template <int BITS>
struct wavelet_matrix {
    fully_indexable_dictionary *fid[BITS];
    int zero_count[BITS];
    wavelet_matrix() {}
    template <typename T>
    wavelet_matrix(vector<T> data) {
        int size = data.size();
        // bit-inversed radix sort
        vector<char> bits(size);
        vector<T> next(size);
        REP_R (k, BITS) {
            typename vector<T>::iterator low  = next.begin();
            typename vector<T>::reverse_iterator high = next.rbegin();
            REP (i, size) {
                bits[i] = bool(data[i] & (1ull << k));
                (bits[i] ? *(high ++) : *(low ++)) = data[i];
            }
            fid[k] = new fully_indexable_dictionary(bits);
            zero_count[k] = low - next.begin();
            reverse(next.rbegin(), high);
            data.swap(next);
        }
    }
    uint64_t quantile(int k, int l, int r) {
        if (k < 0) return -1;
        if (r - l <= k) return 1ull << BITS;
        uint64_t acc = 0;
        REP_R (d, BITS) {
            int lc = fid[d]->rank(1, l);
            int rc = fid[d]->rank(1, r);
            int zero = (r - l) - (rc - lc);
            bool p = (k >= zero);
            if (p) {
                acc |= 1ull << d;
                l = lc + zero_count[d];
                r = rc + zero_count[d];
                k -= zero;
            } else {
                l -= lc;
                r -= rc;
            }
        }
        return acc;
    }
};

const int shift = 1e9;
int main() {
    int n, queries; scanf("%d%d", &n, &queries);
    vector<int> a(n);
    REP (i, n) {
        scanf("%d", &a[i]);
        a[i] += shift;
    }
    wavelet_matrix<31> *wm = new wavelet_matrix<31>(a);
    while (queries --) {
        int l, r, k; scanf("%d%d%d", &l, &r, &k);
        -- l; -- k;
        int result = wm->quantile(k, l, r) - shift;
        printf("%d\n", result);
    }
    return 0;
}
```
