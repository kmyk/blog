---
layout: post
alias: "/blog/2016/06/05/hackerrank-zalando-codesprint-give-me-the-order/"
date: 2016-06-05T19:18:12+09:00
tags: [ "competitive", "writeup", "hackerrank", "treap", "self-balancing-binary-serach-tree" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/give-me-the-order" ]
---

# HackerRank Zalando CodeSprint: Give Me the Order

本番は平衡二分探索木を知らず、解けず。

平衡二分探索木は怖いという印象があったが、実装してみるとけっこう軽かったです。一発ACできた。

## problem

数列$A$が与えられる。
その区間$[l,r)$を削除し先頭に追加するという操作$A \gets ( A\_{l_i \dots r_i-1} \oplus A\_{0 \dots l_i-1} \oplus A\_{r_i \dots n-1} )$が$M$個与えられるので順次実行しその結果の数列を答えよ。

## solution

Use a tree structure which supports merge/split with $O(\log n)$. Then this problem is solved with $O(M \log N)$.

Some languages has such a structure, so you can use it simply.
For example, `Data.Sequence` of Haskell uses a finger tree, and you can get AC using it.

## implementation

If you want to implement it by yourself, the treap is a good choice.
[プログラミングコンテストでのデータ構造 2 ～平衡二分探索木編～](http://www.slideshare.net/iwiwi/2-12188757)が分かりやすかったです。

``` c++
#include <iostream>
#include <tuple>
#include <random>
#include <memory>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

template <typename T>
struct treap {
    typedef T value_type;
    typedef double key_type;
    value_type v;
    key_type k;
    shared_ptr<treap> l, r;
    size_t m_size;
    treap(value_type v)
            : v(v)
            , k(generate())
            , l()
            , r()
            , m_size(1) {
    }
    static shared_ptr<treap> update(shared_ptr<treap> const & t) {
        if (t) {
            t->m_size = 1 + size(t->l) + size(t->r);
        }
        return t;
    }
    static key_type generate() {
        static random_device device;
        static default_random_engine engine(device());
        static uniform_real_distribution<double> dist;
        return dist(engine);
    }
    static size_t size(shared_ptr<treap> const & t) {
        return t ? t->m_size : 0;
    }
    static shared_ptr<treap> merge(shared_ptr<treap> const & a, shared_ptr<treap> const & b) { // destructive
        if (not a) return b;
        if (not b) return a;
        if (a->k > b->k) {
            a->r = merge(a->r, b);
            return update(a);
        } else {
            b->l = merge(a, b->l);
            return update(b);
        }
    }
    static pair<shared_ptr<treap>, shared_ptr<treap> > split(shared_ptr<treap> const & t, size_t i) { // [0, i) [i, n), destructive
        if (not t) return { shared_ptr<treap>(), shared_ptr<treap>() };
        if (i <= size(t->l)) {
            shared_ptr<treap> u; tie(u, t->l) = split(t->l, i);
            return { u, update(t) };
        } else {
            shared_ptr<treap> u; tie(t->r, u) = split(t->r, i - size(t->l) - 1);
            return { update(t), u };
        }
    }
    static shared_ptr<treap> insert(shared_ptr<treap> const & t, size_t i, value_type v) { // destructive
        shared_ptr<treap> l, r; tie(l, r) = split(t, i);
        shared_ptr<treap> u = make_shared<treap>(v);
        return merge(merge(l, u), r);
    }
    static pair<shared_ptr<treap>,shared_ptr<treap> > erase(shared_ptr<treap> const & t, size_t i) { // (t \ t_i, t_t), destructive
        shared_ptr<treap> l, u, r;
        tie(l, r) = split(t, i+1);
        tie(l, u) = split(l, i);
        return { merge(l, r), u };
    }
};

typedef treap<int> T;
int main() {
    int n; cin >> n;
    shared_ptr<T> t;
    repeat (i,n) {
        int a; cin >> a;
        t = T::insert(t, i, a);
    }
    int m; cin >> m;
    while (m --) {
        int l, r; cin >> l >> r;
        -- l;
        shared_ptr<T> a, b, c;
        tie(a, c) = T::split(t, r);
        tie(a, b) = T::split(a, l);
        t = T::merge(T::merge(b, a), c);
    }
    repeat (i,n) {
        if (i) cout << ' ';
        shared_ptr<T> u;
        tie(t, u) = T::erase(t, 0);
        cout << u->v;
    }
    cout << endl;
    return 0;
}
```
