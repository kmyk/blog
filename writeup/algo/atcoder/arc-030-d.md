---
layout: post
alias: "/blog/2016/09/09/arc-030-d/"
date: "2016-09-09T03:28:02+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "rbst", "randomized-binary-search-tree", "persistence", "persistent-tree", "range-add-query", "range-sum-query" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc030/tasks/arc030_4" ]
---

# AtCoder Regular Contest 030 D - グラフではない

永続平衡二分探索木で区間queryをさばく問題。
RBST(randomized binary search tree)は始めて書いたが、Treapは既に持っていたので比較部分だけ修正すればよいので楽。
しかし、遅延されたと表現される区間queryの内部表現の処理の実装はTreap単体と同程度に面倒。

茶会で扱ったのだが、重すぎるので失敗な気がする。
後輩さんらがけっこう優秀なので難易度を上げていくつもりだったがすこし上げすぎた。

## solution

永続平衡二分探索木で区間queryをさばく。実装量も考慮して、使う木はRBSTがよいようだ。木にもよるが$O(Q\log N)$の認識でよさそう。

扱うqueryは区間一様加算、split/merge、区間総和の$3$つである。
中央のものは生の永続平衡二分探索木で扱える。
端の$2$つはsegment木でする際と同じようにする。
ただしsplit/mergeの際に遅延された加算queryの整合性を取るように上手くやる必要がある。
親が増えたり減ったりするとき、親が持っていた加算queryの情報も増えたり減ったりするからである。

TLE, MLEはそれなり。
`shared_ptr`を使うと(私の場合は$1$ケースのTLEだけであったが)TLEが厳しい。
かといって開放処理を放棄するとMLEになる。
適当にpoolを確保して埋まってきたらgarbage collectするようにすると両方間に合う。

## implementation

memo: きれいな永続RBSTはlibraryに追加した

``` c++
#include <iostream>
#include <vector>
#include <tuple>
#include <cstdlib>
#include <random>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;

struct prbst { // persistent randomized binary search tree (specialized)
// fields
    // typedef shared_ptr<prbst> pointer;
    typedef prbst *pointer;
    ll value;
    ll lazy;
    ll sum;
    pointer l, r;
    size_t m_size;
// methods
    static size_t size(pointer t) {
        return t ? t->m_size : 0;
    }
    static pointer merge(pointer a, pointer b) {
        if (not a) return b;
        if (not b) return a;
        if (compare(size(a), size(b))) {
            pointer c = range_append(a, 0, size(a), - b->lazy);
            return new_prbst(b->value, b->lazy, merge(c, b->l), b->r);
        } else {
            pointer c = range_append(b, 0, size(b), - a->lazy);
            return new_prbst(a->value, a->lazy, a->l, merge(a->r, c));
        }
    }
    static pair<pointer, pointer > split(pointer t, size_t i) { // [0, i) [i, n)
        if (not t) return { nullptr, nullptr };
        if (i <= size(t->l)) {
            pointer l, r; tie(l, r) = split(t->l, i);
            l = range_append(l, 0, size(l), t->lazy);
            return { l, new_prbst(t->value, t->lazy, r, t->r) };
        } else {
            pointer l, r; tie(l, r) = split(t->r, i - size(t->l) - 1);
            r = range_append(r, 0, size(r), t->lazy);
            return { new_prbst(t->value, t->lazy, t->l, l), r };
        }
    }
    static pointer insert(pointer t, size_t i, ll value) {
        pointer l, r; tie(l, r) = split(t, i);
        pointer u = new_prbst(value);
        return merge(merge(l, u), r);
    }
    static ll range_concat(pointer t, int l, int r) {
        if (not t) return 0;
        if (l == 0 and r == size(t)) {
            return t->sum;
        } else {
            int n = size(t->l);
            ll acc = 0;
            if (l <= n and n < r) acc += t->value;
            if (l   < n) acc += range_concat(t->l,               l, min(n, r));
            if (n+1 < r) acc += range_concat(t->r, max(0, l-(n+1)),   r-(n+1));
            acc += t->lazy * (r - l);
            return acc;
        }
    }
    static pointer range_append(pointer t, int l, int r, ll lazy) {
        if (not t) return t;
        if (l == 0 and r == size(t)) {
            return new_prbst(t->value, t->lazy + lazy, t->l, t->r);
        } else {
            pointer tl = t->l;
            pointer tr = t->r;
            int n = size(tl);
            ll value = t->value + (l <= n and n < r ? lazy : 0);
            if (l   < n) tl = range_append(tl,               l, min(n, r), lazy);
            if (n+1 < r) tr = range_append(tr, max(0, l-(n+1)),   r-(n+1), lazy);
            return new_prbst(value, t->lazy, tl, tr);
        }
    }
// private:
    prbst() = default;
    prbst(ll value, ll lazy = 0, pointer l = nullptr, pointer r = nullptr)
            : value(value), lazy(lazy), l(l), r(r) {
        m_size = 1 + size(l) + size(r);
        sum = value + lazy * m_size + (l ? l->sum : 0) + (r ? r->sum : 0);
    }
    static bool compare(size_t a, size_t b) {
        static random_device device;
        static default_random_engine engine(device());
        bernoulli_distribution dist(b /(double) (a + b));
        return dist(engine);
    }
// for memory efficiency
    static pointer pool;
    static pointer pool_head;
    static int pool_size;
    static pointer new_prbst(ll value, ll lazy = 0, pointer l = nullptr, pointer r = nullptr) {
        *pool_head = prbst(value, lazy, l, r);
        return pool_head ++;
    }
    static void pool_init() {
        pool_size = ((768ll << 10) << 10) * 0.8 / sizeof(prbst);
        pool = pointer(malloc(pool_size * sizeof(prbst)));
        pool_head = pool;
    }
    static pointer pool_garbage_collect(pointer root) {
        if (pool_head < pool + int(pool_size * 0.95)) return root;
        vector<ll> x; serialize(root, x, 0);
        pool_head = pool;
        root = nullptr;
        repeat (i, x.size()) root = insert(root, i, x[i]);
        return root;
    }
    static void serialize(pointer t, vector<ll> & x, ll lazy) {
        if (not t) return;
        serialize(t->l, x, lazy + t->lazy);
        x.push_back(t->value + lazy + t->lazy);
        serialize(t->r, x, lazy + t->lazy);
    }
};
prbst::pointer prbst::pool;
prbst::pointer prbst::pool_head;
int prbst::pool_size;

int main() {
    prbst::pool_init();
    int n, q; cin >> n >> q;
    prbst::pointer t = nullptr;
    repeat (i,n) {
        int x; cin >> x;
        t = prbst::insert(t, i, x);
    }
    while (q --) {
        t = prbst::pool_garbage_collect(t);
        int typ; cin >> typ;
        if (typ == 1) {
            int a, b, v; cin >> a >> b >> v; -- a;
            t = prbst::range_append(t, a, b, v);
        } else if (typ == 2) {
            int a, b, c, d; cin >> a >> b >> c >> d; -- a; -- c;
            prbst::pointer u = prbst::split(prbst::split(t, d).first, c).second;
            prbst::pointer l = prbst::split(t, a).first;
            prbst::pointer r = prbst::split(t, b).second;
            t = prbst::merge(prbst::merge(l, u), r);
        } else if (typ == 3) {
            int a, b; cin >> a >> b; -- a;
            cout << prbst::range_concat(t, a, b) << endl;
        }
    }
    return 0;
}
```
