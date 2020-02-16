---
layout: post
redirect_from:
  - /blog/2018/04/02/aoj-ritscamp18day3-g/
date: "2018-04-02T22:46:53+09:00"
tags: [ "competitive", "writeup", "aoj", "rupc", "string", "rolling-hash", "greedy", "suffix-array" ]
"target_url": [ "https://onlinejudge.u-aizu.ac.jp/beta/room.html#RitsCamp18Day3/problems/G" ]
---

# AOJ RitsCamp18Day3: G. 検閲により置換 (Censored String)

## solution

rolling hashして貪欲でいいらしい。$O(\sum \|p\_i\| + \|S\| \cdot \sqrt{\sum \|p\_i\|})$。

$1 \le \|p\_1\| + \|p\_2\| + \dots + \|p\_N\| \le 10^5$の制約により長さの種類数$\\#\\{ \|p\_i\| \mid 1 \le i \le N \\} \le 2 \sqrt{10^5}$である。
$S$のある位置を右端として禁止文字列が含まれているかの判定は、これによりrolling hashを使えば一致判定は$O(\sqrt{\sum \|p\_i\|})$。

## note

-   長さの種類数が小さいのは典型だと思う
-   長さの種類数が小さいことに気付かなかったのでtrieとかを使っていい感じに潰してsuffix arrayで頑張ろうとしていた。「TLEだろうけどWAではないことの確認のため投げてみるか」といって投げたらACしてコンテストが終了した (全完)

## implementation


``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }
template <typename T> ostream & operator << (ostream & out, vector<T> const & xs) { REP (i, int(xs.size()) - 1) out << xs[i] << ' '; if (not xs.empty()) out << xs.back(); return out; }

/**
 * @brief suffix array
 * @note O(N (\log N)^2), Manber & Myers, 蟻本
 * @note sa[i] is the index of i-th smallest substring of s, s[sa[i], N)
 * @note rank[i] is the rank of substring s[i, N)
 */
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
int sa_lower_bound(string const & s, vector<int> const & sa, string const & t) { // returns an index on suffix array
    int n = s.size();
    int l = 0, r = n+1; // (l, r]
    while (l + 1 < r) {
        int m = (l + r) / 2;
        (s.compare(sa[m], string::npos, t) < 0 ? l : r) = m;
    }
    return r;
}
int sa_prefix_upper_bound(string const & s, vector<int> const & sa, string const & t) { // returns an index on suffix array
    int n = s.size();
    int l = 0, r = n+1; // (l, r]
    while (l + 1 < r) {
        int m = (l + r) / 2;
        (s.compare(sa[m], t.size(), t) <= 0 ? l : r) = m;
    }
    return r;
}

template <typename T>
struct trie_t {
    T data;
    array<shared_ptr<trie_t>, 26> children;
};
template <typename T>
shared_ptr<trie_t<T> > trie_insert(shared_ptr<trie_t<T> > original_t, string const & s, T data) {
    if (not original_t) original_t = make_shared<trie_t<T> >();
    auto t = original_t;
    for (char c : s) {
        assert (isalpha(c));
        int i = toupper(c) - 'A';
        if (not t->children[i]) t->children[i] = make_shared<trie_t<T> >();
        t = t->children[i];
    }
    t->data = data;
    return original_t;
}
template <typename T>
shared_ptr<trie_t<T> > trie_find(shared_ptr<trie_t<T> > const & t, string const & s, int i) {
    if (t == nullptr) return t;
    if (i == s.length()) return t;
    char c = s[i];
    int j = toupper(c) - 'A';
    return trie_find(t->children[j], s, i + 1);
}

struct string_set {
    shared_ptr<trie_t<char> > root;
    void add(string const & s) {
        root = trie_insert(root, s, '\0');
    }
    bool is_prefix(string const & s) {
        return trie_find(root, s, 0) != nullptr;
    }
};

template <class Monoid, class OperatorMonoid>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::underlying_type, typename OperatorMonoid::target_type>::value, "");
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    const Monoid mon;
    const OperatorMonoid op;
    int n;
    vector<underlying_type> a;
    vector<operator_type> f;
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid(), OperatorMonoid const & a_op = OperatorMonoid())
            : mon(a_mon), op(a_op) {
        n = 1; while (n <= a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
        f.resize(max(0, (2 * n - 1) - n), op.identity());
    }
    void point_set(int i, underlying_type z) {
        assert (0 <= i and i < n);
        point_set(0, 0, n, i, z);
    }
    void point_set(int i, int il, int ir, int j, underlying_type z) {
        if (i == n + j - 1) { // 0-based
            a[i] = z;
        } else if (ir <= j or j+1 <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.identity();
            point_set(2 * i + 1, il, (il + ir) / 2, j, z);
            point_set(2 * i + 2, (il + ir) / 2, ir, j, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    void range_apply(int l, int r, operator_type z) {
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            a[i] = op.apply(z, a[i]);
            if (i < f.size()) f[i] = op.compose(z, f[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.identity();
            range_apply(2 * i + 1, il, (il + ir) / 2, l, r, z);
            range_apply(2 * i + 2, (il + ir) / 2, ir, l, r, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    underlying_type range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    underlying_type range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) { // 0-based
            return a[i];
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return op.apply(f[i], mon.append(
                    range_concat(2 * i + 1, il, (il + ir) / 2, l, r),
                    range_concat(2 * i + 2, (il + ir) / 2, ir, l, r)));
        }
    }
};

struct min_monoid {
    typedef int underlying_type;
    int unit() const { return INT_MAX; }
    int append(int a, int b) const { return min(a, b); }
};
struct write_operator_monoid {
    typedef int underlying_type;
    typedef int target_type;
    int identity() const { return -1; }
    int apply(underlying_type a, target_type b) const { return a == -1 ? b : a; }
    int compose(underlying_type a, underlying_type b) const { return a == -1 ? b : a; }
};

int main() {
    // input
    string s; cin >> s;
    int n; cin >> n;
    vector<string> p(n);
    REP (i, n) cin >> p[i];

    // solve
vector<int> available(n);
iota(ALL(available), 0);
/*
    vector<int> available; {
        vector<int> order(n);
        iota(ALL(order), 0);
        sort(ALL(order), [&](int i, int j) { return p[i].length() > p[j].length(); });
        string_set sset;
        REP (i, n) {
            string p_i = p[i];
            reverse(ALL(p_i));
            if (not sset.is_prefix(p_i)) {
                sset.add(p_i);
                available.push_back(i);
            }
        }
    }
*/
    int len = s.length();
    vector<int> left(len + 1, -1); {
        vector<int> sa, rank; suffix_array(s, sa, rank);
// REP (i, sa.size()) {
    // cerr << i << " : " << s.substr(sa[i]) << endl;
// }
        for (int i : available) {
            int sa_l = sa_lower_bound(s, sa, p[i]);
            int sa_r = sa_prefix_upper_bound(s, sa, p[i]);
// cerr << p[i] << ' ' << sa_l << ' ' << sa_r << endl;
            REP3 (sa_j, sa_l, sa_r) {
                int l = sa[sa_j];
                int r = l + p[i].length();
                chmax(left[r], l);
            }
        }
    }
    constexpr int inf = 1e9 + 7;
    lazy_propagation_segment_tree<min_monoid, write_operator_monoid> segtree(len + 1);
    segtree.point_set(0, 0);
    REP3 (r, 1, len + 1) {
        if (left[r] == -1) continue;
        segtree.point_set(r, segtree.range_concat(0, r) + 1);
        segtree.range_apply(0, left[r] + 1, inf);
    }
    int result = segtree.range_concat(0, len + 1);
/*
    vector<int> dp(len + 1, inf);
    dp[0] = 0;
// cerr << 0 << " : " << dp << endl;
    REP3 (r, 1, len + 1) {
        if (left[r] == -1) continue;
        REP (i, r) {
            chmin(dp[r], dp[i] + 1);
        }
        REP (i, left[r] + 1) {
            dp[i] = inf;
        }
// cerr << r << " : " << dp << endl;
    }
    int result = inf;
    REP (i, len + 1) {
        chmin(result, dp[i]);
    }
*/

    // output
    cout << result << endl;
    return 0;
}
```
