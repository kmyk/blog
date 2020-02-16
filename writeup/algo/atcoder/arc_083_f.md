---
layout: post
date: 2018-09-26T05:41:54+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "implementation", "topological-sort", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc083/tasks/arc083_d" ]
redirect_from:
  - /writeup/algo/atcoder/arc-083-f/
---

# AtCoder Regular Contest 083: F - Collecting Balls

## 解法

### 概要

消せるところから消していく。
消えずに詰まるところは発生するが独立にそれぞれ$2$通り試せばよいことが分かる。
有向根付き森のトポロジカルソートの個数を数える感じになる。
計算量は曖昧だが$O(N \log N)$ぐらいのはず。

### 詳細

ある未使用の行/列にひとつしか点が残っていなければ、その点はその行/列の向きに使用されることが分かる。
これを再帰的にやれば多くが消えて、長方形あるいはそれに近い形で止まる。
次はサンプル4の例で、初期状態:

```
.*..***.
....*...
..*...*.
*....*.*
*.......
...*...*
..*..*..
....*...
```

自明なものを消した後:

```
.v..v**.
....<...
..*...*.
v....<.v
<.......
...v...<
..*..*..
....<...
```

そのような形の左下の点を縦で消すか横で消すかを$2$通り試せばよい。

もちろんこの長方形のような形が連鎖する場合が怖い。
例えば次のような入力の場合。

```
......**
....*.**
.....*..
...**...
...**...
..*.....
**.*....
**......
```

しかしこのような場合は他の部分で点の数が足りず自明に答えが$0$になるため無視してよい。
よって長方形は高々$1$重にしかならない。

一方で長方形が複数独立に出現しうることには注意。
つまり次のような入力である。
しかしこれは適切にそれぞれ計算して後からまとめてやれば済む。

```
**..
**..
..**
..**
```

これを実装すれば解ける。

## メモ

雰囲気でやるだけなのに実装力がないので$6$時間かかった

## 実装

``` c++
#include <algorithm>
#include <cassert>
#include <iostream>
#include <map>
#include <tuple>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

template <int32_t MOD>
struct mint {
    int64_t value;  // faster than int32_t a little
    mint() = default;  // value is not initialized
    mint(int64_t value_) : value(value_) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->value + other.value; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->value - other.value; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->value * int64_t(other.value) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->value += other.value; if (this->value >= MOD) this->value -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->value -= other.value; if (this->value <    0) this->value += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->value = this->value * int64_t(other.value) % MOD; if (this->value < 0) this->value += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->value ? MOD - this->value : 0); }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this, y = 1;
        for (; k; k >>= 1) {
            if (k & 1) y *= x;
            x *= x;
        }
        return y;
    }
    mint<MOD> inv() const { return pow(MOD - 2); }  // MOD must be a prime
};
template <int32_t MOD> ostream & operator << (ostream & out, mint<MOD> n) { return out << n.value; }

template <int32_t MOD>
mint<MOD> fact(int n) {
    static vector<mint<MOD> > memo(1, 1);
    while (n >= memo.size()) {
        memo.push_back(memo.back() * mint<MOD>(memo.size()));
    }
    return memo[n];
}
template <int32_t PRIME>
mint<PRIME> inv_fact(int n) {
    static vector<mint<PRIME> > memo;
    if (memo.size() <= n) {
        int l = memo.size();
        int r = n * 1.3 + 100;
        memo.resize(r);
        memo[r - 1] = fact<PRIME>(r - 1).inv();
        for (int i = r - 2; i >= l; -- i) {
            memo[i] = memo[i + 1] * (i + 1);
        }
    }
    return memo[n];
}

template <int32_t MOD>
mint<MOD> choose(int n, int r) {
    assert (0 <= r and r <= n);
    return fact<MOD>(n) * inv_fact<MOD>(n - r) * inv_fact<MOD>(r);
}


constexpr int MOD = 1e9 + 7;

struct chain_t {
    mint<MOD> cnt;
    int size;
    chain_t() : cnt(1), size(0) {}
    chain_t(mint<MOD> cnt_, int size_) : cnt(cnt_), size(size_) {}
    chain_t operator * (chain_t other) const {
        int next_size = this->size + other.size;
        mint<MOD> next_cnt = this->cnt * other.cnt * choose<MOD>(next_size, size);
        return chain_t(next_cnt, next_size);
    }
};

struct unsat {};

class solver {
    int n;
    vector<int> xs, ys;

    static constexpr char OPENED = 'O';
    static constexpr char CLOSED = 'C';
    vector<map<int, int> > row_none, col_none;  // : z -> (z -> i)
    vector<map<int, int> > row_opened, col_opened;  // : z -> (z -> i)
    vector<map<int, int> > row_closed, col_closed;  // : z -> (z -> i)
    vector<int> row_used, col_used;  // : z -> i
    vector<char> state;
    vector<chain_t> chain;
    vector<tuple<char, int, int> > history;  // only for use_generic()

public:
    solver(int n_, vector<int> const & xs_, vector<int> const & ys_)
             : n(n_), xs(xs_), ys(ys_) {
        row_none.resize(n);
        col_none.resize(n);
        REP (i, 2 * n) {
            int y = ys[i];
            int x = xs[i];
            row_none[y][x] = i;
            col_none[x][y] = i;
        }
        row_opened.resize(n);
        col_opened.resize(n);
        row_closed.resize(n);
        col_closed.resize(n);
        row_used.resize(n, -1);
        col_used.resize(n, -1);
        state.resize(2 * n);
        chain.resize(2 * n);
    }

private:
    void set_state(int i, char next_state) {
        int y = ys[i];
        int x = xs[i];
        if (not state[i]) {
            row_none[y].erase(x);
            col_none[x].erase(y);
        } else if (state[i] == OPENED) {
            row_opened[y].erase(x);
            col_opened[x].erase(y);
        } else if (state[i] == CLOSED) {
            row_closed[y].erase(x);
            col_closed[x].erase(y);
        } else {
            assert (false);
        }
        state[i] = next_state;
        if (not state[i]) {
            row_none[y][x] = i;
            col_none[x][y] = i;
        } else if (state[i] == OPENED) {
            row_opened[y][x] = i;
            col_opened[x][y] = i;
        } else if (state[i] == CLOSED) {
            row_closed[y][x] = i;
            col_closed[x][y] = i;
        }
    }

    chain_t use_generic(int i, bool is_row) {
        int y = ys[i];
        int x = xs[i];

// cerr << "use " << y << " " << x << " " << (is_row ? "<" : "v") << endl;

        // change the state
        int & used = (is_row ? row_used[y] : col_used[x]);
        assert (used == -1);
        history.emplace_back('u', i, is_row);
        used = i;

        // update the graph
        assert (not state[i]);
        history.emplace_back('s', i, state[i]);
        set_state(i, OPENED);

        // run dp
        chain[i] = chain_t();
        auto & opened = (is_row ? row_opened[y] : col_opened[x]);
        auto last = opened.find(is_row ? x : y);
        vector<int> indices;
        for (auto it = opened.begin(); it != last; ++ it) {
            indices.push_back(it->second);
        }
        for (int j : indices) {
// cerr << "j = " << j << " : y = " << ys[j] << ", x = " << xs[j] << " : state = " << state[j] << endl;
            history.emplace_back('s', j, state[j]);
            set_state(j, CLOSED);
            chain[i] = chain[i] * chain[j];
        }
        chain[i].size += 1;

        // return chain
        chain_t acc = chain_t();
        if (is_closable(i)) {
            history.emplace_back('s', i, state[i]);
            set_state(i, CLOSED);
            acc = acc * chain[i];

            auto & opened = (is_row ? col_opened[x] : row_opened[y]);
            vector<int> indices;
            for (auto it : opened) {
                int j = it.second;
                if (is_closable(j)) {
                    indices.push_back(j);
                }
            }
            for (int j : indices) {
                history.emplace_back('s', j, state[j]);
                set_state(j, CLOSED);
                acc = acc * chain[j];
            }
        }
        return acc;
    }

    bool is_closable(int i) {
        assert (state[i] == OPENED);
        int y = ys[i];
        int x = xs[i];
        return row_none[y].lower_bound(x) == row_none[y].end() and col_none[x].lower_bound(y) == col_none[x].end();
    }

    chain_t go_row(int y) {
        if (row_used[y] != -1) return chain_t();
        if (row_none[y].empty()) {
            throw unsat {};
        } else if (row_none[y].size() == 1) {
            int x, i; tie(x, i) = *row_none[y].begin();
            chain_t c = use_generic(i, true);
            return c * go_col(x);
        } else {
            return chain_t();  // nop
        }
    }

    chain_t go_col(int x) {
        if (col_used[x] != -1) return chain_t();
        if (col_none[x].empty()) {
            throw unsat {};
        } else if (col_none[x].size() == 1) {
            int y, i; tie(y, i) = *col_none[x].begin();
            chain_t c = use_generic(i, false);
            return c * go_row(y);
        } else {
            return chain_t();  // nop
        }
    }

    chain_t propagate_units() {
        chain_t acc;
        REP (y, n) acc = acc * go_row(y);
        REP (x, n) acc = acc * go_col(x);
        return acc;
    }

    vector<int> get_rects() {
        vector<int> rects;
        REP (i, 2 * n) {
            int y = ys[i];
            int x = xs[i];
            if (row_used[y] == -1 and col_used[x] == -1) {
                assert (not state[i]);
                if (row_none[y].begin()->first == x and col_none[x].begin()->first == y) {
                    rects.push_back(i);
                }
            }
        }
        return rects;
    }

    void save_history() {
        history.clear();
    }
    void load_history() {
        while (not history.empty()) {
            char type; int i, arg; tie(type, i, arg) = history.back();
            history.pop_back();
            int y = ys[i];
            int x = xs[i];

            if (type == 'u') {
                int & used = (arg ? row_used[y] : col_used[x]);
                used = -1;
            } else if (type == 's') {
                set_state(i, arg);
            } else {
                assert (false);
            }
        }
    }

    void debug_print() const {
        REP_R (y, n) {
            REP (x, n) {
                char c;
                if (row_none[y].count(x)) {
                    c = '*';
                } else if (row_opened[y].count(x) or row_closed[y].count(x)) {
                    c = '?';
                    int i = row_used[y];
                    if (i != -1 and y == ys[i] and x == xs[i]) {
                        c = '<';
                    }
                    int j = col_used[x];
                    if (j != -1 and y == ys[j] and x == xs[j]) {
                        assert (c == '?');
                        c = 'v';
                    }
                    assert (c != '?');
                } else {
                    c = '.';
                }
                cerr << c;
            }
            cerr << endl;
        }
        REP (is_row, 2) {
            cerr << "---" << endl;
            REP (z, n) {
                int i = (is_row ? row_used : col_used)[z];
                char c = (i == -1 ? '-' : state[i]);
                cerr << (is_row ? 'y' : 'x') << " = " << z << " : state = " << c;
                if (c == OPENED) cerr << " : dp = " << chain[i].cnt.value << " : size = " << chain[i].size;
                cerr << endl;
            }
        }
        cerr << endl;
    }

public:
    mint<MOD> operator () () {
        try {
            chain_t acc = chain_t();
            acc = acc * propagate_units();
// debug_print();
            vector<int> rects = get_rects();
            for (int i : rects) {
                if (state[i]) continue;
                int y = ys[i];
                int x = xs[i];
                assert (row_used[y] == -1 and col_used[x] == -1);

                save_history();
                chain_t c1 = use_generic(i, false);
                c1 = c1 * propagate_units();
                load_history();
                chain_t c2 = use_generic(i, true);
                c2 = c2 * propagate_units();
                assert (c1.size == c2.size);
                chain_t c(c1.cnt + c2.cnt, c1.size);
                acc = acc * c;

// debug_print();
            }
            return acc.cnt;
        } catch (unsat e) {
            return 0;
        }
    }
};

int main() {
    int n; cin >> n;
    vector<int> x(2 * n), y(2 * n);
    REP (i, 2 * n) {
        cin >> x[i] >> y[i];
        -- x[i]; -- y[i];
    }
    cout << solver(n, x, y)().value << endl;
    return 0;
}
```
