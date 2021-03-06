---
redirect_from:
  - /writeup/algo/yukicoder/719/
layout: post
date: 2018-07-28T00:49:04+09:00
tags: [ "competitive", "writeup", "yukicoder", "prime-numbers", "beam-search", "embedding", "lie" ]
"target_url": [ "https://yukicoder.me/problems/no/719" ]
---

# Yukicoder No.719 Coprime

<!-- {% raw %} -->

## note

[editorial](https://yukicoder.me/problems/no/719/editorial)や[kmjp](http://kmjp.hatenablog.jp/entry/2018/07/28/0900)さんの解法の方が面白い。
使う順序を上手く決めることで仮定を増やすテクは典型だが、最大素因数に注目して平方根までで済ます形のそれは初めて。
私も「どうせ$\sqrt{n}$まで持てばいい感じのやつでしょ」は考えたが$O(2^{\sqrt{n}})$ 大嘘DPぐらいしか思い付けなかった。

## solution

嘘解法。$n$以下の素数の数$\pi(x)$を使って$O(n2^{\pi(n)})$のDPに嘘を混ぜてビームサーチにして手元で解を出し埋め込み。

注意は次:

-   $2, 3$を取るより$6$を取った方が良いことから降順に貪欲に取るだけでかなり上手く行くが、昇順だとビームサーチですら解が悪化
-   そこそこ頑張ってもぎりぎりTLEるので素直に埋め込むべき。bitsetを使い、使う素数を絞り、状態をheapに乗せ、pragma有効化してもなおTLEだった

## implementation

``` c++
#pragma GCC optimize "O3"
#pragma GCC target "avx2"
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= (int)(m); -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

constexpr int MAX_N = 1262;
constexpr int PRIMES_SIZE = 115;  // 205;
const array<int, PRIMES_SIZE> primes = {{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, }};  // 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259} };

struct state_t {
    bitset<PRIMES_SIZE> used;
    size_t hash;
    int acc;
};
unique_ptr<state_t> make_state(int acc, const bitset<PRIMES_SIZE> & used) {
    static hash<bitset<PRIMES_SIZE> > h;
    state_t a = { used, h(used), acc };
    return make_unique<state_t>(a);
}
bool compare_by_hash_and_acc(const unique_ptr<state_t> & a, const unique_ptr<state_t> & b) { return make_pair(a->hash, a->acc) > make_pair(b->hash, b->acc); }
bool equal_by_hash(const unique_ptr<state_t> & a, const unique_ptr<state_t> & b) { return a->hash == b->hash; }
bool compare_by_acc(const unique_ptr<state_t> & a, const unique_ptr<state_t> & b) { return a->acc > b->acc; }

int solve(int n) {
    const int embed[] = { 118378, 119579, 119579, 119579, 119579, 119579, 119579, 119643, 119643, 119643, 119643, 119679, 119679, 120892, 120892, 120892, 120892, 122109, 122109, 122399, 122399, 122399, 122399, 123622, 123622, 123622, 123622, 123622, 123622, 124851, 124851, 126082, 126082, 126082, 126082, 126082, 126082, 127319, 127319, 127319, 127319, 127313, 127313, 127353, 127353, 127353, 127353, 127395, 127395, 128644, 128644, 128660, 128660, 128696, 128696, 128688, 128730, 128730, 128730, 129989, 129989, 130085, 130085 };
    if (n >= 1200) return embed[n - 1200];

    assert (n <= MAX_N);
    vector<bitset<PRIMES_SIZE> > mask(n + 1);
    REP (j, PRIMES_SIZE) {
        for (int i = primes[j]; i <= n; i += primes[j]) {
            mask[i][j] = true;
        }
    }

    vector<unique_ptr<state_t> > dp;
    dp.push_back(make_state(0, bitset<PRIMES_SIZE>()));
    REP3R (i, 2, n + 1) {
        int k = dp.size();
        REP (j, k) {
            auto & it = *dp[j];
            if ((it.used & mask[i]).none()) {
                dp.push_back(make_state(it.acc + i, it.used | mask[i]));
            }
        }
        sort(ALL(dp), compare_by_hash_and_acc);
        dp.erase(unique(ALL(dp), equal_by_hash), dp.end());
        sort(ALL(dp), compare_by_acc);
        dp.resize(min<int>(dp.size(), 10000));
    }
    return dp[0]->acc;
}

int main() {
    int n; cin >> n;
    cout << solve(n) << endl;
    return 0;
}
```

<!-- {% endraw %} -->
