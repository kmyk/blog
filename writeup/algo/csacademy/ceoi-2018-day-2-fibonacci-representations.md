---
layout: post
date: 2018-08-17T04:24:57+09:00
tags: [ "competitive", "writeup", "csacademy", "fibonacci", "dp", "segment-tree", "matrix", "dynamic-construction", "range" ]
"target_url": [ "https://csacademy.com/contest/ceoi-2018-day-2/task/fibonacci-representations-small/", "https://csacademy.com/contest/ceoi-2018-day-2/task/fibonacci-representations-big/" ]
redirect_from:
  - /writeup/algo/cs-academy/ceoi-2018-day-2-fibonacci-representations/
---

# CS Academy CEOI 2018 Day 2: Fibonacci Representations Small / Fibonacci Representations Big

## problem

Fibonacci数列$F$を考える。
正整数$p$に対し$X(p)$を、$p$を互いに異なるfibonacci数の和として表現する方法の数とする。
数列$a_1, a_2, \dots, a_n$が与えられる。
$p_1 = F _ {a_1}, p_2 = F _ {a_1} + F _ {a_2}, \dots$ に対し $X(p_1), X(p_2), \dots$ を求めよ。

## solution

Fibonacci数の和をZeckendorfの表現してこれに沿ってDP。
普通にDPを毎回やり直すと$O(n)$かかるので行列を動的構築segment木に乗せる。
計算量は$O(n \log n \log \max a_i)$。

まず正整数$p$のFibonacci数の和による表現で正規なものを考えてみよう。
後のことを考えると大きいものから貪欲に使っていった場合の形で保持するのが正解。
これはZeckendorfの表現と呼ばれる (らしい)。
その更新は悪意がない限りほぼ定数時間。
部分点ならここまでで十分で、愚直な再帰を書けばよい。
ただし $$(F _ r + F _ {r - 2} + F _ {r - 4} + \dots + F _ l) + F _ r = F _ {r + 1} + F _ {r - 1} + F _ {r - 3} + \dots + F _ {l + 1} + F _ {l - 2}$$ というのがあるので満点にはならない。
これを解決したいならそのような区間の集合を管理すればよい。

$p$のZeckendorfの表現があるときに$X(p)$を求めたい。
これは小さい方からのDPで求まる。
表現に項$F _ n$が含まれているとき $$F _ n = F _ {n - 1} + F _ {n - 2} = F _ {n - 1} + F _ {n - 3} + F _ {n - 4} = \dots$$ と再帰的に展開でき、かつひとつ下の項に邪魔されて止まるので、ひとつ下の項との距離にほぼ比例する数だけ$X(p)$が大きくなる。
その差分の偶奇によっては厄介で、ひとつ下の項が展開されたかされてないかで場合分けが必要。
これは小さい側から$i$項目まで決めて$i$項目を展開したかどうかを$j$としてその部分までの表現の数$\mathrm{dp}(i, j)$というDPで求まる。
$\mathrm{dp}(i + 1, j) \in \mathbb{N}$ は $\mathrm{dp}(i, 0), \mathrm{dp}(i, 1)$ にのみ依存する。
このふたつを $x, y$ と置けば$\mathrm{dp}(i, j)$に依存しない多項式 $\mathrm{dp}(i + 1, j) \in \mathbb{N}[x, y]$ と見做せかつ線形なので、この形でなら好きな順序で更新できる。
こうして書き直したDPは整理するとつまり$2 \times 2$行列の積を取っていることになる。
これを動的構築segment木に乗せれば終了。
部分点なら$F_i$に対応した行列を位置$i$に置くことになるが、満点には区間$[l, r)$に対応した行列を位置$l$や位置$r$に置くことになる。

## note

コーナーに気付かず実装して投げたらTLEし、部分点でさえ実装は面倒だったのに捨ててさらに面倒なのを書く気力がなくて終了。
満点には切断結合のできる平衡二分木の上で遅延評価をしないとだめだと思ってたのも一因。
コンテスト終了後に次を見て現実的な実装量だと気付いたので頑張って書きました。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">とりあえずゼッケンドルフの表現で表す方法を考える。<a href="https://t.co/nUhLYP7uDj">https://t.co/nUhLYP7uDj</a><br>nがゼッケンドルフの表現でかけてるときに、n+F_kがゼッケンドルフの表現でかければ良くて、これはうまくやればO(log k)でできる。<br>「1こ飛ばしで使われる区間」の集合を管理すると良い。</p>&mdash; (nは自然数) (@n_vip) <a href="https://twitter.com/n_vip/status/1030153679926513664?ref_src=twsrc%5Etfw">2018年8月16日</a></blockquote>
<blockquote class="twitter-tweet" data-conversation="none" data-lang="ja"><p lang="ja" dir="ltr">そこから答えを求めるためには、それぞれの区間について定まる2x2行列の積を取れば良い。行列は自分と隣の区間にしか寄らないので、集合を更新するときに処理すれば計算量は抑えら得られる。あとは長さ1e9の区間のセグメントツリーをunordered_map使って持てば全体の積が求まるんだけど、定数がきつい</p>&mdash; (nは自然数) (@n_vip) <a href="https://twitter.com/n_vip/status/1030153681457401856?ref_src=twsrc%5Etfw">2018年8月16日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Zeckendorfの表現というのは知らなかった。
動的構築segment木を `unordered_map` でやる発想も知らなかった。
ただし構築時に右端を決め打ちする必要がある。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

template <class Monoid>
struct dynamic_segment_tree { // on monoid
    typedef Monoid monoid_type;
    typedef typename Monoid::underlying_type underlying_type;
    struct node_t {
        int left, right; // indices on pool
        underlying_type value;
    };
    deque<node_t> pool;
    int root; // index
    int width; // of the tree
    int size; // the number of leaves
    Monoid mon;
    dynamic_segment_tree(Monoid const & a_mon = Monoid()) : mon(a_mon) {
        node_t node = { -1, -1, mon.unit() };
        pool.push_back(node);
        root = 0;
        width = 1;
        size = 1;
    }
protected:
    int create_node(int parent, bool is_right) {
        // make a new node
        int i = pool.size();
        node_t node = { -1, -1, mon.unit() };
        pool.push_back(node);
        // link from the parent
        assert (parent != -1);
        int & ptr = is_right ? pool[parent].right : pool[parent].left;
        assert (ptr == -1);
        ptr = i;
        return i;
    }
    underlying_type get_value(int i) {
        return i == -1 ? mon.unit() : pool[i].value;
    }
public:
    void point_set(int i, underlying_type z) {
        assert (0 <= i);
        while (width <= i) {
            node_t node = { root, -1, pool[root].value };
            root = pool.size();
            pool.push_back(node);
            width *= 2;
        }
        point_set(root, -1, false, 0, width, i, z);
    }
    void point_set(int i, int parent, bool is_right, int il, int ir, int j, underlying_type z) {
        if (il == j and ir == j + 1) { // 0-based
            if (i == -1) {
                i = create_node(parent, is_right);
                size += 1;
            }
            pool[i].value = z;
        } else if (ir <= j or j + 1 <= il) {
            // nop
        } else {
            if (i == -1) i = create_node(parent, is_right);
            point_set(pool[i].left,  i, false, il, (il + ir) / 2, j, z);
            point_set(pool[i].right, i, true,  (il + ir) / 2, ir, j, z);
            pool[i].value = mon.append(get_value(pool[i].left), get_value(pool[i].right));
        }
    }
    underlying_type range_concat(int l, int r) {
        assert (0 <= l and l <= r);
        if (width <= l) return mon.unit();
        return range_concat(root, 0, width, l, min(width, r));
    }
    underlying_type range_concat(int i, int il, int ir, int l, int r) {
        if (i == -1) return mon.unit();
        if (l <= il and ir <= r) { // 0-based
            return pool[i].value;
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return mon.append(
                    range_concat(pool[i].left,  il, (il + ir) / 2, l, r),
                    range_concat(pool[i].right, (il + ir) / 2, ir, l, r));
        }
    }
};

template <typename T, size_t H, size_t W>
using matrix = array<array<T, W>, H>;
template <typename T, size_t N>
matrix<T, N, N> matrix_unit() {
    matrix<T, N, N> a = {};
    REP (i, N) a[i][i] = 1;
    return a;
}
template <typename T, size_t A, size_t B, size_t C>
matrix<T, A, C> operator * (matrix<T, A, B> const & a, matrix<T, B, C> const & b) {
    matrix<T, A, C> c = {};
    REP (y, A) REP (z, B) REP (x, C) c[y][x] += a[y][z] * b[z][x];
    return c;
}
template <typename T, size_t N>
matrix<T, N, N> matrix_pow(matrix<T, N, N> x, uint64_t k) {
    matrix<T, N, N> y = matrix_unit<T, N>();
    for (uint64_t i = 1; i <= k; i <<= 1) {
        if (k & i) y = y * x;
        x = x * x;
    }
    return y;
}

template <int32_t MOD>
struct mint {
    int64_t data;  // faster than int32_t a little
    mint() = default;  // data is not initialized
    mint(int64_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
};

constexpr int MOD = 1e9 + 7;

struct dp_t {
    typedef struct {
        int l, r;  // [l, r]
        matrix<mint<MOD>, 2, 2> f;
    } underlying_type;

    static matrix<mint<MOD>, 2, 2> matrix_from_dist(int dist) {
        matrix<mint<MOD>, 2, 2> g;
        g[0][0] = 1;
        g[0][1] = 1;
        if (dist % 2 == 0) {
            g[1][0] = dist / 2;
            g[1][1] = dist / 2;
        } else {
            g[1][0] = (dist - 1) / 2;
            g[1][1] = (dist - 1) / 2 + 1;
        }
        return g;
    }
    static underlying_type make(int l, int r) {
        assert ((r - l) % 2 == 1);
        underlying_type a;
        a.l = l;
        a.r = r;
        if (a.r != -1) {
            a.f = matrix_pow(matrix_from_dist(1), (r - l) / 2);
        }
        return a;
    }

    underlying_type unit() const {
        return dp_t::make(-2, -1);
    }
    underlying_type append(underlying_type const & a, underlying_type const & b) const {
        if (a.r == -1) return b;
        if (b.r == -1) return a;
        assert ((a.l == 0 and a.r == 1) or a.r < b.l);
        underlying_type c;
        c.l = a.l;
        c.r = b.r;
        int dist = b.l - a.r;
        auto g = dp_t::matrix_from_dist(dist);
        c.f = b.f * g * a.f;
        return c;
    }
};

vector<mint<MOD> > solve(int n, vector<int> const & a) {
    set<pair<int, int> > b;  // a set of pairs (r, l) for ranges [l, r) of 101010...1
    dynamic_segment_tree<dp_t> segtree;
    segtree.point_set(0, dp_t::make(0, 1));

    auto remove = [&](int l, int r) {
        assert (b.count(make_pair(r, l)));
        b.erase(make_pair(r, l));
        segtree.point_set(l, dp_t().unit());
    };
    auto add = [&](int l, int r) {
        assert (l < r and (r - l) % 2 == 1);
        b.emplace(r, l);
        segtree.point_set(l, dp_t::make(l, r));
    };

    function<void (int)> add1 = [&](int i) {
        if (i < 0) {
            // nop
        } else if (i == 0) {
            add1(1); // since F_2 \ne F_1 + F_0 in this sequence
        } else {
            auto it = b.lower_bound(make_pair(i, INT_MAX));
            int r = -1, l = -2;  // the nearest range whose r > i
            int r1 = -1, l1 = -2;  // the nearest range whose r <= i
            if (it == b.end()) {
                if (not b.empty()) {
                    tie(r1, l1) = *b.rbegin();
                }
            } else {
                tie(r, l) = *it;
                if (it != b.begin()) {
                    tie(r1, l1) = *prev(it);
                }
            }
            if (l <= i and i < r and (i - l) % 2 == 0) {  // F_i already exists
                remove(l, r);
                if (l + 1 < i) add(l + 1, i);
                add1(l - 2);
                add1(r);
            } else if (l <= i and i < r and (i - l) % 2 == 1) {  // F_{i + 1} and F_{i - 1} exist
                remove(l, r);
                add(l, i);
                add1(r);
            } else if (l == i + 1) {  // F_{i + 1} exists
                remove(l, r);
                add1(r);
            } else if (r1 == i) {  // F_{i - 1} exists
                remove(l1, r1);
                if (l1 < r1 - 2) add(l1, r1 - 2);
                add1(r1 + 1);
            } else if (l == i + 2 and i == r1 + 1) {  // F_{i + 2} and F_{i - 2} exist
                remove(l, r);
                remove(l1, r1);
                add(l1, r);
            } else if (l == i + 2) {  // F_{i + 2} exists
                remove(l, r);
                add(i, r);
            } else if (i == r1 + 1) {  // F_{i - 2} exists
                remove(l1, r1);
                add(l1, r1 + 2);
            } else {  // nothing around F_i
                add(i, i + 1);
            }
        }
    };

    vector<mint<MOD> > x(n);
    REP (i, n) {
        add1(a[i]);
        auto dp = segtree.range_concat(0, segtree.width);
        x[i] = dp.f[0][0] + dp.f[1][0];  // sum of f * (1, 0)^t
    }
    return x;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n);
    REP (i, n) scanf("%d", &a[i]);

    // solve
    auto x = solve(n, a);

    // output
    for (auto x_i : x) {
        printf("%d\n", (int)x_i.data);
    }
    return 0;
}
```
