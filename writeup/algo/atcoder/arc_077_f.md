---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-077-f/
  - /blog/2018/01/15/arc-077-f/
date: "2018-01-15T15:32:09+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "string" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc077/tasks/arc077_d" ]
---

# AtCoder Regular Contest 077: F - SS

まったく分からなかった。
editorialを見た (英語版の方が詳しい)。
でもそのeditorialもよく分からなかった。
不可能ではないが得られる経験値のわりに時間がかかりすぎる気がして諦めましたごめんなさい。
本番でどうやって実装まで漕ぎ着ければいいのだろうか。

## solution

$g^n(S')$が常に$f^n(S)$のprefixであるような関数$g$を定義し$f^{10^{100}}(S)$を求める代わりに$g^{10^{100}}(S')$を考えても同じである。
与えられた$S$を$f(S)$で置き換えても変わらないので$S$は偶文字列であるとしてよい。
よって$S, f(S), f^2(S), \dots$は常に偶文字列であるが$S = T^2$が冗長なことから、$g$を$T$の関数として選ぶ。
具体的には$g(T)^2 = f(T^2)$であるようにする。

まず$g^n(S')$が常に$f^n(S)$のprefixであることについて。
特に、文字列$T$を固定し、数学的帰納法によって任意の自然数$n \in \mathbb{N}$に対し$g^n(T)^2 = f^n(T^2)$を示す。

-   $0$のときは明らか。
-   $n + 1$について。$g^{n + 1}(T)^2 = g(g^n(T))^2 = f(g^n(T)^2) = f(f^n(T^2)) = f^{n + 1}(T^2)$。

ここで具体的な$f(S)$の計算。
$f(S)$は$O(\|S\|)$かけて計算すればよい。
ある$A$とそのprefixである$B$を使って$S = A^kB$であって$f(S) = A^{k'}$となるので、そのような$A$を全列挙し全て試す。
サンプル1から分かるように、$A$が最短のものを選ぶのは嘘。
計算量は$O(\|S\|)$。

次に$g(T)$の計算。
$g(T)$の最小化を考えているので、$T$の末尾と$g(T)$の先頭をできるだけ長く一致させたい。
これは$T = A^kB$となるような$A, B$で$B$が$A$のprefixなものだけを考えればよい。
ひとまず$A, B$は適切に選ばれたとする。

-   $B = \epsilon$のとき。$f(S) = f(A^{2k}) = A^{2k+2}$であり$g(A^k) = A^{k+1}$。
-   $B \ne \epsilon$のとき。$S = A^kBA^kB \to A^kBA^{k+1} = (A^kBA)A^k \to (A^kBA)^2$とできて$f(A^kB) = A^kBA^{k+1}BA$、つまり$g(A^kB) = A^kBA$。

どちらの場合でも$g(T) = TA$となり、またこのことから$A$を最小に選ぶのが正解であることが分かる。
次に$g^2(T)$を求めたい。$g(T) = A^kBA = {A'}^{k'}B'$となる最短の$A'$を考える。

-   $B = \epsilon$のとき。変わらず$A' = A$で$B' = \epsilon$。よって$g^2(A^k) = A^{k+2}$。
-   $B \ne \epsilon$のとき。明らかに$A^kB$は$A'$の候補。
    $\|{A'}^{k'}\| \lt \|A^kB\|$な最短の$A'$で$B'$をprefixとするものが存在したと仮定する。
    -   **(ここで$\|A'\| \bmod \|A\|$で場合分けをしGCDや周期性を上手くやるっぽい。分からなかったので次は認めるとする)**

    $A' = A^kB$。よって$g^2(A^kB) = A^kB \cdot A \cdot A^kB$。

まとめると一般に$g^2(T) = g(T)T$であることが分かる。

あとはこの$g^2(T) = g(T)T$の式を元に再帰とかを書けばよい。
$B = \epsilon$の場合は周期性を使って$O(\|S\|)$にできる。
そうでなくて$B \ne \epsilon$の場合はfibonacci数列に従って長さが増えるので$O(\|S\| + \log r)$。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

struct rolling_hash {
    static constexpr int size = 4;
    static const int32_t prime[size];
    static int32_t base[size];
    static struct base_initializer_t {
        base_initializer_t() {
            random_device device;
            default_random_engine gen(device());
            REP (i, size) {
                base[i] = uniform_int_distribution<int32_t>(256, prime[i] - 1)(gen);
            }
        }
    } base_initializer;
public:
    array<int32_t, size> data;
    rolling_hash() : data({}) {}
    rolling_hash(char c) {
        REP (i, size) data[i] = c;
    }
    void push_back(char c) {
        REP (i, size) {
            data[i] = (data[i] *(int64_t) base[i] + c) % prime[i];
        }
    }
    rolling_hash & operator -= (rolling_hash const & other) {
        REP (i, size) {
            data[i] -= other.data[i];
            if (data[i] < 0) data[i] += prime[i];
        }
        return *this;
    }
    rolling_hash & operator <<= (array<int32_t, size> const & pow_base) {
        REP (i, size) {
            data[i] = data[i] *(int64_t) pow_base[i] % prime[i];
        }
        return *this;
    }
    bool operator == (rolling_hash const & other) const {
        return equal(ALL(data), other.data.begin());
    }
    bool operator != (rolling_hash const & other) const {
        return not (*this == other);
    }
};
const int32_t rolling_hash::prime[size] = { 1000000027, 1000000033, 1000000087, 1000000093 };
int32_t rolling_hash::base[size];
rolling_hash::base_initializer_t rolling_hash::base_initializer;

struct rolling_hash_cumulative_sum {
    rolling_hash_cumulative_sum() = default;
    int size;
    vector<rolling_hash> data;
    vector<array<int32_t, rolling_hash::size> > pow_base;
    rolling_hash_cumulative_sum(string const & s) {
        size = s.length();
        data.resize(size + 1);
        data[0] = rolling_hash();
        REP (i, size) {
            data[i + 1] = data[i];
            data[i + 1].push_back(s[i]);
        }
        pow_base.resize(size + 1);
        fill(ALL(pow_base[0]), 1);
        REP (i, size) {
            REP (j, rolling_hash::size) {
                pow_base[i + 1][j] = pow_base[i][j] *(int64_t) rolling_hash::base[j] % rolling_hash::prime[j];
            }
        }
    }
    rolling_hash get_range(int l, int r) {
        assert (0 <= l and l <= r and r <= size);
        return rolling_hash(data[r]) -= (rolling_hash(data[l]) <<= pow_base[r - l]);
    }
};

template <class Func>
void enumerate_cycles(string const & s, Func func) {
    rolling_hash_cumulative_sum hash(s);
    REP3 (cycle, 1, s.length() + 1) {
        bool is_cycle = true;
        auto x = hash.get_range(0, cycle);
        int i = cycle;
        for (; i + cycle < s.length() and is_cycle; i += cycle) {
            auto y = hash.get_range(i, i + cycle);
            if (x != y) is_cycle = false;
        }
        if (is_cycle) {
            auto y = hash.get_range(i, s.length());
            auto z = hash.get_range(0, s.length() - i);
            if (y != z) is_cycle = false;
        }
        if (is_cycle) {
            if (not func(cycle)) {
                return;
            }
        }
    }
}

string delta_f(string const & s) {
    int result_cycle = s.length();
    int result_delta_length = s.length();
    enumerate_cycles(s, [&](int cycle) {
        int a = s.length() / cycle;
        int b = s.length() % cycle;
        int delta_length = 0;
        if (b != 0) {
            delta_length += cycle - b;
            a += 1;
        }
        if (a % 2 == 1) {
            delta_length += cycle;
        }
        if (delta_length == 0) {
            delta_length += 2 * cycle;
        }
        if (delta_length < result_delta_length) {
            result_delta_length = delta_length;
            result_cycle = cycle;
        }
        return true;
    });
    int cycle = result_cycle;
    int a = s.length() / cycle;
    int b = s.length() % cycle;
    string delta;
    if (b != 0) {
        delta += s.substr(b, cycle - b);
        a += 1;
    }
    if (a % 2 == 1) {
        delta += s.substr(0, cycle);
    }
    if (delta.length() == 0) {
        delta += s.substr(0, cycle);
        delta += s.substr(0, cycle);
    }
    return delta;
}

array<ll, 26> count_alphabets(string const & s) {
    array<ll, 26> cnt = {};
    for (char c : s) cnt[c - 'a'] += 1;
    return cnt;
}
array<ll, 26> operator + (array<ll, 26> const & a, array<ll, 26> const & b) {
    array<ll, 26> c;
    REP (i, 26) c[i] = a[i] + b[i];
    return c;
}
array<ll, 26> operator - (array<ll, 26> const & a, array<ll, 26> const & b) {
    array<ll, 26> c;
    REP (i, 26) c[i] = a[i] - b[i];
    return c;
}
string half(string const & s) {
    assert (s.substr(0, s.length() / 2) == s.substr(s.length() / 2));
    return s.substr(0, s.length() / 2);
}

int main() {
    // input
    string s; cin >> s;
    ll l, r; cin >> l >> r; -- l;

    // solve
    s += delta_f(s);
    string t = half(s);
    string gt = half(s + delta_f(s));
    vector<ll> len(2);
    len[0] =  t.size();
    len[1] = gt.size();
    vector<array<ll, 26> > cnt(2);
    cnt[0] = count_alphabets( t);
    cnt[1] = count_alphabets(gt);
    while (len.back() < 2 * r + 10000) {
        int i = len.size();
        len.push_back(len[i - 1] + len[i - 2]);
        cnt.push_back(cnt[i - 1] + cnt[i - 2]);
    }
    function<array<ll, 26> (ll)> func = [&](ll r) {
        if (r < len[0]) return count_alphabets(t.substr(0, r));
        int i = 0;
        while (len[i + 1] < r) ++ i;
        return cnt[i] + func(r - len[i]);
    };
    auto result = func(r) - func(l);

    // output
    REP (i, 26) {
        cout << result[i] << ' ';
    }
    cout << endl;
    return 0;
}
```
