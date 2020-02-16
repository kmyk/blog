---
layout: post
date: 2018-08-04T08:59:50+09:00
tags: [ "competitive", "writeup", "atcoder", "njpc", "suffix-array", "string", "stack" ]
"target_url": [ "https://beta.atcoder.jp/contests/njpc2017/tasks/njpc2017_g" ]
---

# NJPC2017: G - 交換法則

## solution

最も愚直には区間DP $O(|S|^4)$ 。
最も小さい文字に着目し分割するのを再帰的にやれば $O(|S|^3)$ で、最悪ケースが難しいためか通ってしまう。
suffix arrayを用いて高速に部分文字列を比較すれば $O(|S|^2)$ にできる。

文字列 $S$ に文字 `a` が含まれるとしてよい。
$S$ の先頭の文字が `a` でなければ明らかに再構築不能。
加えて、 `a` 以外の文字は必ず `a` の後ろに移動してしまうため、先にそれらを結合して `axxx, axxx, axxx, ..., axxx` のような状態にしてしまってよい。

$(S_1, S_2, \dots, S_n)$ と並んでいるとする。
それらの中で最小のものを $A = S_i$ とする。
$(A, X, X, X, A, X, X, X, A, X, X, X, \dots, A, X, X, X)$ のような状況であると仮定してよい。
$XA = X$ であること、 $AXXXA$ を作ってから後ろに $X$ を足すより $AXXX$ と $AX$ にしてから足した方が条件が緩いことから、 $(A X X X, A X X X, A X X X \dots, A X X X)$ のように結合するのが同様に最適。
これを再帰的にやれば終了。

初期の列の長さが $|S|$ で毎回長さを $1$ 以上減らせる (減らなかったらそこで打ち切れる) ので $O(|S|)$ 回の操作。
最悪ケースは `aaaaaa...aaab` のような形の場合。
なおeditorialではこのような場合への対策を入れて $O(\log |S|)$ 回に落としている。
操作は文字列比較が$O(1)$なら$O(|S|)$。
よって全体で $O(|S|^2)$。

## note

-   けっこう好き
-   操作で列を毎回舐めてるから計算量が落ちないので、stackで必要な箇所を必要な回数だけ操作すれば落ちるっぽい
    -   出展: kmjpさんの[記事](http://kmjp.hatenablog.jp/entry/2017/01/30/0930)中のmaroonrkさんの解法
    -   この落とし方は覚えておきたい

## implementation

通らないと思っていたが通ってしまった $O(|S|^3)$:

``` c++
#include <bits/stdc++.h>
#define ALL(x) begin(x), end(x)
using namespace std;

bool solve(string const & original_s) {
    vector<string> s;
    for (char c : original_s) {
        s.push_back(string() + c);
    }
    while (true) {
        string const & min_c = *min_element(ALL(s));
        if (s.front() != min_c) return false;
        vector<string> t;
        for (string const & c : s) {
            if (c == min_c) {
                t.emplace_back();
            }
            t.back() += c;
        }
        if (t.size() == 1) return true;
        if (t.size() == s.size()) return true;
        s.swap(t);
    }
}

int main() {
    string s; cin >> s;
    cout << (solve(s) ? "Yes" : "No") << endl;
    return 0;
}
```

気合いを入れてclassを生やしたがどうみても牛刀だった $O(|S|^2)$:

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
#define unittest_name_helper(counter) unittest_ ## counter
#define unittest_name(counter) unittest_name_helper(counter)
#define unittest __attribute__((constructor)) void unittest_name(__COUNTER__) ()
using namespace std;

void suffix_array(string const & s, vector<int> & sa, vector<int> & rank) {
    int n = s.length();
    sa.resize(n + 1);
    rank.resize(n + 1);
    REP (i, n + 1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    auto rankf = [&](int i) { return i <= n ? rank[i] : -1; };
    vector<int> nxt(n + 1);
    for (int k = 1; k <= n; k <<= 1) {
        auto cmp = [&](int i, int j) { return make_pair(rank[i], rankf(i + k)) < make_pair(rank[j], rankf(j + k)); };
        sort(sa.begin(), sa.end(), cmp);
        nxt[sa[0]] = 0;
        REP3 (i, 1, n + 1) {
            nxt[sa[i]] = nxt[sa[i - 1]] + (cmp(sa[i - 1], sa[i]) ? 1 : 0);
        }
        rank.swap(nxt);
    }
}
vector<int> longest_common_prefix_array(string const & s, vector<int> const & sa, vector<int> const & rank) {
    int n = s.length();
    vector<int> lcp(n);
    int h = 0;
    lcp[0] = 0;
    REP (i, n) {
        int j = sa[rank[i] - 1];
        if (h > 0) -- h;
        while (j + h < n and i + h < n and s[j + h] == s[i + h]) ++ h;
        lcp[rank[i] - 1] = h;
    }
    return lcp;
}

template <class Semilattice>
struct sparse_table {
    typedef typename Semilattice::underlying_type underlying_type;
    vector<vector<underlying_type> > table;
    Semilattice lat;
    sparse_table() = default;
    sparse_table(vector<underlying_type> const & data, Semilattice const & a_lat = Semilattice())
            : lat(a_lat) {
        int n = data.size();
        int log_n = 32 - __builtin_clz(n);
        table.resize(log_n, vector<underlying_type>(n));
        table[0] = data;
        REP (k, log_n - 1) {
            REP (i, n) {
                table[k + 1][i] = i + (1ll << k) < n ?
                    lat.append(table[k][i], table[k][i + (1ll << k)]) :
                    table[k][i];
            }
        }
    }
    underlying_type range_concat(int l, int r) const {
        if (l == r) return lat.unit();  // if there is no unit, remove this line
        assert (0 <= l and l <= r and r <= table[0].size());
        int k = 31 - __builtin_clz(r - l);  // log2
        return lat.append(table[k][l], table[k][r - (1ll << k)]);
    }
};
struct min_semilattice {
    typedef int underlying_type;
    int unit() const { return INT_MAX; }
    int append(int a, int b) const { return min(a, b); }
};

/**
 * @brief compare substrings of a string with O(1) using suffix arrays
 */
class comparable_string_view_factory {
public:
    class comparable_string_view {
    public:
        const comparable_string_view_factory *factory;
        const int l, r;
    private:
        friend class comparable_string_view_factory;
        comparable_string_view(const comparable_string_view_factory *factory_, int l_, int r_)
                : factory(factory_), l(l_), r(r_) {
        }
    public:
        inline bool empty() const { return r == 0; }
        inline size_t size() const { return r - l; }
        inline char operator [] (size_t i) const {
            assert (0 <= i and i < size());
            return factory->s[l + i];
        }
        inline bool operator < (comparable_string_view const & other) const {
            assert (this->factory == other.factory);
            return this->factory->strcmp(this->l, this->r, other.l, other.r) < 0;
        }
        inline bool operator == (comparable_string_view const & other) const {
            assert (this->factory == other.factory);
            return this->factory->strcmp(this->l, this->r, other.l, other.r) == 0;
        }
        inline bool operator != (comparable_string_view const & other) const {
            assert (this->factory == other.factory);
            return this->factory->strcmp(this->l, this->r, other.l, other.r) != 0;
        }
    };
private:
    string s;
    vector<int> sa, rank;
    sparse_table<min_semilattice> lcp;
public:
    comparable_string_view_factory() = default;
    comparable_string_view_factory(string const & s_)
            : s(s_) {
        suffix_array(s, sa, rank);
        vector<int> lcp_ = longest_common_prefix_array(s, sa, rank);
        lcp = sparse_table<min_semilattice>(lcp_);
    }
    comparable_string_view make_view(int l, int r) const {
        assert (0 <= l and l <= r and r <= s.length());
        return comparable_string_view(this, l, r);
    }
private:
    int strcmp(int l1, int r1, int l2, int r2) const {
        int rank_l, rank_r; tie(rank_l, rank_r) = minmax({ rank[l1], rank[l2] });
        int k = lcp.range_concat(rank_l, rank_r);
        if (min(r1 - l1, r2 - l2) <= k) {
            return (r1 - l1) - (r2 - l2);
        } else {
            return rank[l1] - rank[l2];
        }
    }
};
typedef comparable_string_view_factory::comparable_string_view comparable_string_view;

unittest {
    default_random_engine gen;
    REP (iteration, 100) {
        int length = uniform_int_distribution<int>(10, 100)(gen);
        string s;
        REP (i, length) {
            s += uniform_int_distribution<char>('A', 'Z')(gen);
        }
        comparable_string_view_factory factory(s);
        REP (iteration, 100) {
            int l1 = uniform_int_distribution<int>(0, length / 2)(gen);
            int r1 = uniform_int_distribution<int>(l1, length)(gen);
            int l2 = uniform_int_distribution<int>(0, length / 2)(gen);
            int r2 = uniform_int_distribution<int>(l2, length)(gen);
            auto view1 = factory.make_view(l1, r1);
            auto view2 = factory.make_view(l2, r2);
            auto sub1 = s.substr(l1, r1 - l1);
            auto sub2 = s.substr(l2, r2 - l2);
            assert ((view1 < view2) == (sub1 < sub2));
        }
    }
}

bool solve(string const & original_s) {
    comparable_string_view_factory factory(original_s);
    vector<comparable_string_view> s;
    REP (i, original_s.length()) {
        s.push_back(factory.make_view(i, i + 1));
    }
    while (true) {
        comparable_string_view const & min_c = *min_element(ALL(s));
        if (s.front() != min_c) return false;
        vector<comparable_string_view> t;
        for (auto const & c : s) {
            if (c == min_c) {
                t.push_back(c);
            } else {
                auto d = t.back();
                t.pop_back();
                t.push_back(factory.make_view(d.l, c.r));
            }
        }
        if (t.size() == 1) return true;
        if (t.size() == s.size()) return true;
        s.swap(t);
    }
}

int main() {
    string s; cin >> s;
    cout << (solve(s) ? "Yes" : "No") << endl;
    return 0;
}
```
