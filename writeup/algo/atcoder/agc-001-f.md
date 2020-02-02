---
layout: post
alias: "/blog/2018/03/06/agc-001-f/"
title: "AtCoder Grand Contest 001: F - Wide Swap"
date: "2018-03-06T01:11:28+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "sort", "bubble-sort", "insertion-sort", "binary-search", "red-black-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc001/tasks/agc001_f" ]
---

## solution

つよい木。非想定解。$O(N (\log N)^2)$。

置換$P \in \mathfrak{S}\_N$の逆元$Q = P^{-1}$をとると次のような問題に帰着される:

>   数列$Q$が与えられる。隣り合う要素で差が$K$以上のものをswapしてよい。辞書順最小にせよ。

bubble sortすれば$O(N^2)$。
これはinsertion sortをしても同じ解が得られる。
区間最小値/点削除/点挿入を処理できる木を持ってきて二分探索と更新をすれば$O(N (\log N)^2)$となる。

## implementation

木の実装は赤黒木を基本に遅延伝播を乗せてsegment木っぽくすればよい。
ついでにreverseなど多めに乗せたのが悪かったのかもだがTLEが厳しかったので、Treapで誤魔化したりするのは危なそう。


赤黒木の実装は以下を参考にした。
ただし下ふたつは2018/03/06時点では`mergeSub`の`a.rank == b.rank`なケースにバグがあるので写経するなら修正が必要。

-   [赤黒木 - Wikipedia](https://ja.wikipedia.org/wiki/%E8%B5%A4%E9%BB%92%E6%9C%A8)
-   [コピー＆ペースト (Copy and Paste) JOI 春合宿 2012 Day 4 解説](https://www.ioi-jp.org/camp/2012/2012-sp-tasks/2012-sp-day4-copypaste-slides.pdf)
-   [赤黒木(marge/split) - Algoogle](http://algoogle.hadrori.jp/algorithm/rbtree_merge.html)

``` c++
#pragma GCC optimize "O3,omit-frame-pointer,inline"
#pragma GCC target "avx,tune=native"
#define NDEBUG
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
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

/**
 * @note almost all operations are O(log N)
 */
template <class Monoid, class OperatorMonoid>
class lazy_propagation_red_black_tree {
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;

    enum color_t { BLACK, RED };
    struct node_t {
        bool is_leaf;
        underlying_type data;
        operator_type lazy;  // NOTE: this->lazy is already applied to this->data
        bool reversed;
        color_t color;
        int rank;
        int size;
        node_t *left;
        node_t *right;
        node_t() = default;
        node_t(underlying_type const & a_data)
                : is_leaf(true)
                , data(a_data)
                , color(BLACK)
                , rank(0)
                , size(1) {
        }
        node_t(node_t *l, node_t *r, color_t c)  // non-leaf node
                : is_leaf(false)
                , data(Monoid().append(l->data, r->data))
                , lazy(OperatorMonoid().identity())
                , reversed(false)
                , color(c)
                , rank(max(l->rank + (l->color == BLACK),
                           r->rank + (r->color == BLACK)))
                , size(l->size + r->size)
                , left(l)
                , right(r) {
        }
    };
    struct node_deleter {
        void operator () (node_t *t) const {
            assert (t != nullptr);
            if (not t->is_leaf) {
                (*this)(t->right);
                (*this)(t->left);
            }
            delete t;
        }
    };

    static void propagate_only_operator(node_t *a) {
        OperatorMonoid op;
        if (not a->is_leaf) {
            if (a->lazy != op.identity()) {
                auto const & l = a->left;
                auto const & r = a->right;
                l->data = op.apply(a->lazy, l->data);
                r->data = op.apply(a->lazy, r->data);
                if (not l->is_leaf) l->lazy = op.compose(a->lazy, l->lazy);
                if (not r->is_leaf) r->lazy = op.compose(a->lazy, r->lazy);
                a->lazy = op.identity();
            }
        }
    }
    static void propagate_only_reverse(node_t *a) {
        if (not a->is_leaf) {
            if (a->reversed) {
                auto const & l = a->left;
                auto const & r = a->right;
                if (not l->is_leaf) l->reversed = not l->reversed;
                if (not r->is_leaf) r->reversed = not r->reversed;
                swap(a->left, a->right);  // CAUTION: auto const & l, r are destroyed
                a->reversed = false;
            }
        }
    }
    static void propagate(node_t *a) {
        propagate_only_operator(a);
        propagate_only_reverse(a);
    }

    /**
     * @note trees a, b are consumed  (at set_left()/set_right())
     */
    static node_t *merge(node_t *a, node_t *b) {
        if (a == nullptr) return b;
        if (b == nullptr) return a;
        node_t *c = merge_relax(a, b);
        c->color = BLACK;
        return c;
    }
    /*
     * @note the root of returned tree may violates the color constraint
     * @note merge_relax(a, b)->rank == max(rank->a, rank->b) + 1
     */
    static node_t *merge_relax(node_t *a, node_t *b) {
        if ((a->rank) < b->rank) {
            assert (not b->is_leaf);
            propagate(b);
            return set_left(b, merge_relax(a, b->left));
        } else if (a->rank > b->rank) {
            assert (not a->is_leaf);
            propagate(a);
            return set_right(a, merge_relax(a->right, b));
        } else {
            a->color = BLACK;
            b->color = BLACK;
            return new node_t(a, b, RED);
        }
    }
    static node_t *set_left(node_t *b, node_t *c) {
        if (b->color == BLACK and c->color == RED and c->left->color == RED) {
            if (b->right->color == BLACK) {
                *b = node_t(c->right, b->right, RED);
                *c = node_t(c->left, b, BLACK);
                swap(b, c);
            } else {
                b->right->color = BLACK;
                c->color = BLACK;
                *b = node_t(c, b->right, RED);
            }
        } else {
            *b = node_t(c, b->right, b->color);
        }
        return b;
    }
    static node_t *set_right(node_t *a, node_t *c) {
        if (a->color == BLACK and c->color == RED and c->right->color == RED) {
            if (a->left->color == BLACK) {
                *a = node_t(a->left, c->left, RED);
                *c = node_t(a, c->right, BLACK);
                swap(a, c);
            } else {
                a->left->color = BLACK;
                c->color = BLACK;
                *a = node_t(a->left, c, RED);
            }
        } else {
            *a = node_t(a->left, c, a->color);
        }
        return a;
    }

    /**
     * @note tree a is consumed  (at explicit delete and merge())
     */
    static pair<node_t *, node_t *> split(node_t *a, int k) {
        if (k == 0) {
            return make_pair( nullptr, a );
        }
        assert (a != nullptr);
        if (k == a->size) {
            return make_pair( a, nullptr );
        }
        assert (not a->is_leaf);
        propagate(a);
        node_t *a_left  = a->left;
        node_t *a_right = a->right;
        delete a;
        if (k < a_left->size) {
            node_t *l, *r; tie(l, r) = split(a_left, k);
            return make_pair( l, merge(r, a_right) );
        } else if (k > a_left->size) {
            node_t *l, *r; tie(l, r) = split(a_right, k - a_left->size);
            return make_pair( merge(a_left, l), r );
        } else {
            return make_pair( a_left, a_right );
        }
    }

    static void range_apply(node_t *a, int l, int r, operator_type const & func) {
        Monoid mon;
        OperatorMonoid op;
        if (l == r) return;
        if (l == 0 and r == a->size) {
            a->data = op.apply(func, a->data);
            if (not a->is_leaf) a->lazy = op.compose(func, a->lazy);
            return;
        }
        assert (not a->is_leaf);
        propagate(a);
        int k = a->left->size;
        if (r <= k) {
            range_apply(a->left, l, r, func);
        } else if (k <= l) {
            range_apply(a->right, l - k, r - k, func);
        } else {
            range_apply(a->left, l, k, func);
            range_apply(a->right, 0, r - k, func);
        }
        a->data = op.apply(a->lazy, mon.append(a->left->data, a->right->data));
    }

    static underlying_type range_concat(node_t *a, int l, int r) {
        assert (l < r);
        if (l == 0 and r == a->size) return a->data;
        assert (not a->is_leaf);
        propagate(a);
        int k = a->left->size;
        if (r <= k) {
            return range_concat(a->left, l, r);
        } else if (k <= l) {
            return range_concat(a->right, l - k, r - k);
        } else {
            return Monoid().append(
                    range_concat(a->left, l, k),
                    range_concat(a->right, 0, r - k));
        }
    }

    static node_t *reverse(node_t *a, int l, int r) {
        // TODO: find ways to do without split. there may be clever ways using recursion
        if (l == r) return a;
        node_t *bl, *br; tie(bl, br) = split(a, r);
        node_t *bm; tie(bl, bm) = split(bl, l);
        if (not bm->is_leaf) bm->reversed = not bm->reversed;
        return merge(merge(bl, bm), br);
    }

    static void point_set(node_t *a, int i, underlying_type const & value) {
        if (a->is_leaf) {
            assert (i == 0);
            a->data = value;
        } else {
            propagate_only_reverse(a);  // should we do full propagation?
            if (i < a->left->size) {
                point_set(a->left, i, value);
            } else {
                point_set(a->right, i - a->left->size, value);
            }
            a->data = OperatorMonoid().apply(a->lazy,
                    Monoid().append(a->left->data, a->right->data));
        }
    }

    static underlying_type & point_get(node_t *a, int i) {
        if (a->is_leaf) {
            assert (i == 0);
            return a->data;
        } else {
            propagate(a);
            if (i < a->left->size) {
                return point_get(a->left, i);
            } else {
                return point_get(a->right, i - a->left->size);
            }
        }
    }

private:
    unique_ptr<node_t, node_deleter> root;

public:
    lazy_propagation_red_black_tree() = default;
    lazy_propagation_red_black_tree(node_t *a_root)
            : root(a_root) {
    }

    static lazy_propagation_red_black_tree merge(lazy_propagation_red_black_tree & l, lazy_propagation_red_black_tree & r) {
        node_t *a = l.root.release();
        node_t *b = r.root.release();
        if (a == nullptr) return lazy_propagation_red_black_tree(b);
        if (b == nullptr) return lazy_propagation_red_black_tree(a);
        return lazy_propagation_red_black_tree(merge(a, b));
    }
    pair<lazy_propagation_red_black_tree, lazy_propagation_red_black_tree> split(int k) {
        assert (0 <= k and k <= size());
        node_t *l, *r; tie(l, r) = split(root.release(), k);
        return make_pair( lazy_propagation_red_black_tree(l), lazy_propagation_red_black_tree(r) );
    }

    void insert(int i, underlying_type const & data) {
        assert (0 <= i and i <= size());
        if (empty()) {
            root.reset(new node_t(data));
            return;
        } else {
            node_t *l, *r; tie(l, r) = split(root.release(), i);
            root.reset( merge(merge(l, new node_t(data)), r) );
        }
    }
    void erase(int i) {
        assert (0 <= i and i < size());
        node_t *l, *r; tie(l, r) = split(root.release(), i + 1);
        node_t *m; tie(l, m) = split(l, i);
        node_deleter()(m);
        root.reset( merge(l, r) );
    }

    void point_set(int i, underlying_type const & value) {
        assert (0 <= i and i < size());
        point_set(root.get(), i, value);
    }
    underlying_type const & point_get(int i) const {
        assert (0 <= i and i < size());
        return point_get(const_cast<node_t *>(root.get()), i);
    }

    void range_apply(int l, int r, operator_type const & func) {
        assert (0 <= l and l <= r and r <= size());
        if (l == r) return;
        range_apply(root.get(), l, r, func);
    }
    underlying_type const range_concat(int l, int r) const {
        assert (0 <= l and l <= r and r <= size());
        if (l == r) return Monoid().unit();
        return range_concat(const_cast<node_t *>(root.get()), l, r);
    }
    void reverse(int l, int r) {
        assert (0 <= l and l <= r and r <= size());
        if (not root) return;
        root.reset( reverse(root.release(), l, r) );
    }

    void push_back(underlying_type const & data) {
        root.reset( merge(root.release(), new node_t(data)) );
    }
    void push_front(underlying_type const & data) {
        root.reset( merge(new node_t(data), root.release()) );
    }
    void pop_back() {
        int k = size() - 1;
        auto lr = split(root.release(), k);
        root.reset(lr.first);
        node_deleter()(lr.second);
    }
    void pop_front() {
        auto lr = split(root.release(), 1);
        node_deleter()(lr.first);
        root.reset(lr.second);
    }
    int size() const {
        return root ? root.get()->size : 0;
    }
    bool empty() const {
        return not root;
    }
    void clear() {
        root = nullptr;
    }
};

struct min_monoid {
    typedef int underlying_type;
    int unit() const { return INT_MAX; }
    int append(int a, int b) const { return min(a, b); }
};
struct identity_operator_monoid {
    typedef char underlying_type;
    typedef int target_type;
    char identity() const { return '\0'; }
    int apply(char a, int b) const { return b; }
    char compose(char a, char b) const { return '\0'; }
};
typedef lazy_propagation_red_black_tree<min_monoid, identity_operator_monoid> tree;


int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    vector<int> p(n);
    REP (i, n) scanf("%d", &p[i]);

    // solve
    vector<int> que(n);
    REP (i, n) {
        que[p[i] - 1] = i;
    }
    tree q;
    REP (r, n) {
        int l = binsearch(0, r, [&](int m) {
            return q.range_concat(m, r) >= que[r] + k;
        });
        q.insert(l, que[r]);
    }
    REP (i, n) {
        int q_i = q.point_get(i);
        p[q_i] = i + 1;
    }

    // output
    for (int p_i : p) {
        printf("%d\n", p_i);
    }
    return 0;
}
```
