---
layout: post
date: 2018-07-02T20:13:43+09:00
tags: [ "competitive", "writeup", "atcoder", "codeflyer", "parsing", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/bitflyer2018-final-open/tasks/bitflyer2018_final_e" ]
---

# codeFlyer （bitFlyer Programming Contest）: E - 数式とクエリ

## implementation

再帰降下構文解析。
答えの値の配列を区間Affine変換/点取得のsegment木に乗せて計算しながら構文木を畳み込む。
実装を頑張る。
<span>$O(|S| \log Q)$</span>。

なんらかの道で解法に辿り着いたわけなのだが「雰囲気でやった」の表現しかできない。
クエリ先読みして値で整列しsegment木でまとめて計算みたいのは典型。
列の各点を変えた場合どうなるのかを左右からの累積和を貼り合わせる感じも典型で、最後は残らなかったが、この方向で考えていたら出たように思う。

## solution

``` c++
#include <algorithm>
#include <cassert>
#include <iostream>
#include <memory>
#include <numeric>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

template <class OperatorMonoid>
struct dual_segment_tree {
    typedef typename OperatorMonoid::underlying_type operator_type;
    typedef typename OperatorMonoid::target_type underlying_type;
    int n;
    vector<operator_type> f;
    vector<underlying_type> a;
    const OperatorMonoid op;
    dual_segment_tree() = default;
    dual_segment_tree(int a_n, underlying_type initial_value, OperatorMonoid const & a_op = OperatorMonoid()) : op(a_op) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(n, initial_value);
        f.resize(n-1, op.unit());
    }
    underlying_type point_get(int i) { // 0-based
        underlying_type acc = a[i];
        for (i = (i+n)/2; i > 0; i /= 2) { // 1-based
            acc = op.apply(f[i-1], acc);
        }
        return acc;
    }
    void range_apply(int l, int r, operator_type z) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            if (i < f.size()) {
                f[i] = op.append(z, f[i]);
            } else {
                a[i-n+1] = op.apply(z, a[i-n+1]);
            }
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, f[i]);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, f[i]);
            f[i] = op.unit();
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
        }
    }
};

template <int MOD>
struct linear_operator_monoid {
    typedef pair<int, int> underlying_type;
    typedef int target_type;
    linear_operator_monoid() = default;
    underlying_type unit() const {
        return make_pair(1, 0);
    }
    underlying_type append(underlying_type g, underlying_type f) const {
        target_type fst = g.first *(ll) f.first % MOD;
        target_type snd = (g.second + g.first *(ll) f.second) % MOD;
        return make_pair(fst, snd);
    }
    target_type apply(underlying_type f, target_type x) const {
        return (f.first *(ll) x + f.second) % MOD;
    }
};

struct expr_t;
struct term_t;
struct value_t;

struct expr_t {
    vector<pair<bool, shared_ptr<term_t> > > terms;
    int size;
};
struct term_t {
    vector<shared_ptr<value_t> > values;
    int size;
};
struct value_t {
    bool is_a;
    shared_ptr<expr_t> expr;
    int size;
};

shared_ptr<expr_t> parse_expr(const char **s);
shared_ptr<term_t> parse_term(const char **s);
shared_ptr<value_t> parse_value(const char **s);

shared_ptr<expr_t> parse_expr(const char **s) {
    auto e = make_shared<expr_t>();
    e->terms.emplace_back(true, parse_term(s));
    e->size = e->terms.back().second->size;
    while (**s == '+' or **s == '-') {
        char c = **s;
        ++ *s;
        e->terms.emplace_back(c == '+', parse_term(s));
        e->size += e->terms.back().second->size;
    }
    return e;
}
shared_ptr<term_t> parse_term(const char **s) {
    auto t = make_shared<term_t>();
    t->values.push_back(parse_value(s));
    t->size = t->values.back()->size;
    while (**s == '*') {
        ++ *s;
        t->values.push_back(parse_value(s));
        t->size += t->values.back()->size;
    }
    return t;
}
shared_ptr<value_t> parse_value(const char **s) {
    auto v = make_shared<value_t>();
    char c = **s;
    ++ *s;
    if (c == 'a') {
        v->is_a = true;
        v->size = 1;
    } else {
        v->is_a = false;
        assert (c == '(');
        v->expr = parse_expr(s);
        v->size = v->expr->size;
        assert (**s == ')');
        ++ *s;
    }
    return v;
}

constexpr int MOD = 1e9 + 7;
typedef dual_segment_tree<linear_operator_monoid<MOD> > segtree_t;

struct solver_t {
    string const & s;
    int n, q;
    vector<int> const & a, b, x;

    vector<int> order;
    segtree_t segtree;

    solver_t(string const & s, int n, int q, vector<int> const & a, vector<int> const & b, vector<int> const & x)
            : s(s), n(n), q(q), a(a), b(b), x(x),
              order(q), segtree(q, 0) {
        const char *ptr = s.c_str();
        auto e = parse_expr(&ptr);
        iota(ALL(order), 0);
        sort(ALL(order), [&](int i, int j) { return b[i] < b[j]; });
        evaluate_expr(e, 0);
    }

    pair<int, int> range_on_rank(int l, int r) {
        int rank_ql = binsearch(0, q, [&](int i) { return b[order[i]] >= l; });
        int rank_qr = binsearch(0, q, [&](int i) { return b[order[i]] >= r; });
        return make_pair(rank_ql, rank_qr);
    }
    void range_apply_on_query(int l, int r, pair<int, int> f) {
        int rank_ql, rank_qr; tie(rank_ql, rank_qr) = range_on_rank(l, r);
        segtree.range_apply(rank_ql, rank_qr, f);
    }

    int evaluate_expr(shared_ptr<expr_t> const & e, int l0) {
        // evaluate children
        vector<int> values;
        int l = l0;
        for (auto it : e->terms) {
            bool is_plus; shared_ptr<term_t> t; tie(is_plus, t) = it;
            int value = evaluate_term(t, l);
            if (not is_plus) value = (MOD - value) % MOD;
            int r = l + t->size;
            values.push_back(value);
            l = r;
        }
        int sum_values = accumulate(ALL(values), 0ll) % MOD;

        // update query results
        l = l0;
        REP (i, e->terms.size()) {
            bool is_plus = e->terms[i].first;
            int fst = (is_plus ? 1 : MOD - 1);
            int snd = (sum_values - values[i] + MOD) % MOD;
            int r = l + e->terms[i].second->size;
            range_apply_on_query(l, r, make_pair(fst, snd));
            l = r;
        }

        return sum_values;
    }

    int evaluate_term(shared_ptr<term_t> const & t, int l0) {
        int k = t->values.size();

        // evaluate children
        vector<int> values;
        int l = l0;
        for (auto v : t->values) {
            int value = evaluate_value(v, l);
            values.push_back(value);
            l += v->size;
        }

        // make cumulative sums
        vector<int> prod_values(k + 1);
        prod_values[0] = 1;
        REP (i, k) {
            prod_values[i + 1] = prod_values[i] *(ll) values[i] % MOD;
        }
        vector<int> prod_values_reversed(k + 1);
        prod_values_reversed.back() = 1;
        REP_R (i, k) {
            prod_values_reversed[i] = prod_values_reversed[i + 1] *(ll) values[i] % MOD;
        }

        // update query results
        l = l0;
        REP (i, t->values.size()) {
            int r = l + t->values[i]->size;
            int fst = prod_values[i] *(ll) prod_values_reversed[i + 1] % MOD;
            range_apply_on_query(l, r, make_pair(fst, 0));
            l = r;
        }
        return prod_values.back();
    }

    int evaluate_value(shared_ptr<value_t> const & v, int l) {
        if (v->is_a) {
            int rank_ql, rank_qr; tie(rank_ql, rank_qr) = range_on_rank(l, l + 1);
            REP3 (rank_qi, rank_ql, rank_qr) {
                int qi = order[rank_qi];
                assert (l == b[qi]);
                segtree.range_apply(rank_qi, rank_qi + 1, make_pair(0, x[qi]));
            }
            return a[l];

        } else {
            return evaluate_expr(v->expr, l);
        }
    }
};

int main() {
    // input
    string s; cin >> s;
    int n = count(ALL(s), 'a');
    int q; cin >> q;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    vector<int> b(q), x(q);
    REP (i, q) {
        cin >> b[i] >> x[i];
        -- b[i];
    }

    // solve
    solver_t solver(s, n, q, a, b, x);

    // output
    vector<int> answer(q);
    REP (i, q) {
        answer[solver.order[i]] = solver.segtree.point_get(i);
    }
    REP (i, q) {
        cout << answer[i] << endl;
    }
    return 0;
}
```
