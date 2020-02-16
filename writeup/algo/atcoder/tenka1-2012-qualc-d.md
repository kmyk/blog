---
layout: post
alias: "/blog/2017/07/04/tenka1-2012-qualc-d/"
date: "2017-07-04T22:54:03+09:00"
tags: [ "competitive", "writeup", "atcoder", "tenka1", "dp", "frontier", "lie", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2012-qualc/tasks/tenka1_2012_12" ]
---

# 天下一プログラマーコンテスト2012 予選C: D - ゆうびんやさんのお花畑

模擬国内のH問題の関連から名前が上がっていたので解いた。

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">そんなあなたに練習問題！<a href="https://t.co/y5tl8yv6jI">https://t.co/y5tl8yv6jI</a></p>&mdash; chokudai(高橋 直大) (@chokudai) <a href="https://twitter.com/chokudai/status/881759147531788289">July 3, 2017</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

## solution

フロンティア法。定数倍高速化 + 嘘枝刈り + 乱択。フロンティア法による状態数$X \approx 5800$が乗って$O(XHW2^W\alpha(W))$。

$1$行ずつ決めていくDPをする。
その行より上の行全ての道/花畑の状態を記憶すると状態数が爆発するので、道の接続関係だけを記憶するようにする。
これをフロンティア法と呼ぶらしい。
辿り着けない位置に道を作る必要はないので、全ての家と全て道がひとつの連結成分になれば終了。
家は周囲が全て木/花畑のときは新規な連結成分とし、そうでなくすでに接続されている場合は木のように扱うと楽。
解法としてはこれだけ。

ただし素直に実装すると$20$倍、定数倍最適化しても$4$倍足りなかった。
Dijkstraや最小全域木で答えの下界を求めて枝刈りしても$2$倍遅くて間に合わなかった。
そこでbeam searchのようにして結果が悪そうなものをバッサリ落としてしまい、またそれによるWAを回避する方策として盤面をランダムに$n \times 90^\circ$回転させることで、なんとかACが得られた。

なお最悪ケースとしては次のようにほとんど `.` なもの。

```
10 10
.........H
..........
..........
..........
..........
..........
..........
..........
..........
H........H
```

実装の選択肢としては、

-   $1$行ずつまとめて決定する
-   $1$マスずつ順に決定する

があるが、上の方が実装が軽いかつおそらく速い。
また、盤面を斜めに$45^\circ$回転させてからやることも考えられるが、速度はよく分からないが実装は確実に面倒。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <random>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

template <int N>
struct disjoint_sets {
    array<char, N> data;
    disjoint_sets() { whole(fill, data, -1); }
    bool is_root(int i) { return data[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (data[i] = find_root(data[i])); }
    int set_size(int i) { return - data[find_root(i)]; }
    int union_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            data[i] += data[j];
            data[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

constexpr int max_w = 10;
struct state_t {
    array<char, max_w> conn; // connectivity, must be normalized
    char area; // of road
};
void normalize(array<char, max_w> & xs) {
    int n = xs.size();
    array<char, max_w * 2> f;
    whole(fill, f, -1);
    int k = 0;
    repeat (i, n) if (xs[i] != -1) {
        if (f[xs[i]] == -1) {
            f[xs[i]] = k ++ ;
        }
        xs[i] = f[xs[i]];
    }
}
int count_components(array<char, max_w> const & conn) {
    int cnt = 0;
    for (int it : conn) {
        setmax(cnt, it + 1);
    }
    return cnt;
}
bool is_connected(array<char, max_w> const & conn) {
    return count_components(conn) <= 1;
}

state_t append(state_t const & a, string row, int flower) {
    int w = row.size();
    repeat (x, w) {
        if (flower & (1 << x)) {
            assert (row[x] == '.');
            row[x] = '#';
        }
    }
    char b_area = a.area + whole(count, row, '.');
    array<char, max_w> b_conn;
    whole(fill, b_conn, -1);
    disjoint_sets<2 * max_w> ds;
    repeat (x, w) {
        if (row[x] == '.') {
            if (x - 1 >= 0 and row[x - 1] == '.') {
                b_conn[x] = b_conn[x - 1];
            } else {
                b_conn[x] = x + w;
            }
            if (a.conn[x] != -1) ds.union_sets(a.conn[x], b_conn[x]);
        } else if (row[x] == 'H') {
            bool is_isolated = true;
            if (a.conn[x] != -1) is_isolated = false;
            if (x - 1 >= 0 and row[x - 1] == '.') is_isolated = false;
            if (x + 1 <  w and row[x + 1] == '.') is_isolated = false;
            if (is_isolated) {
                b_conn[x] = x + w;
            }
        }
    }
    if (count_components(a.conn) == 1 and whole(count, b_conn, -1) == max_w) {
        return (state_t) { b_conn, b_area };
    } else {
        vector<char> used(2 * w);
        repeat (x, w) if (b_conn[x] != -1) {
            b_conn[x] = ds.find_root(b_conn[x]);
            used[b_conn[x]] = true;
        }
        repeat (x, w) if (a.conn[x] != -1) {
            if (not used[ds.find_root(a.conn[x])]) {
                return (state_t) { {}, -1 }; // invalid
            }
        }
        normalize(b_conn);
        return (state_t) { b_conn, b_area };
    }
}

uint64_t pack(array<char, max_w> const & conn) {
    constexpr int width = 16;
    static_assert(max_w + 1 <= width, "");
    uint64_t packed = 0;
    repeat (x, max_w) {
        packed *= width;
        packed += conn[x] + 1;
    }
    return packed;
}
array<char, max_w> unpack(uint64_t packed) {
    constexpr int width = 16;
    static_assert(max_w + 1 <= width, "");
    array<char, max_w> conn;
    repeat_reverse (x, max_w) {
        conn[x] = packed % width - 1;
        packed /= width;
    }
    return conn;
}


vector<string> rotate(int h, int w, vector<string> const & f) {
    vector<string> g(w, string(h, '\0'));
    repeat (y, h) {
        repeat (x, w) {
            g[w - x - 1][y] = f[y][x];
        }
    }
    return g;
}


int main() {
    // input
    int h, w; cin >> h >> w;
    vector<string> f(h);
    repeat (y, h) cin >> f[y];
    // solve
    default_random_engine gen((random_device()()));
    for (int k = uniform_int_distribution<int>(0, 3)(gen); k; -- k) { // *MAGIC*
        f = rotate(h, w, f);
        swap(h, w);
    }
    whole(reverse, f); // *MAGIC*
    int road_count = 0;
    int tree_count = 0;
    int last_house_y;
    repeat (y, h) repeat (x, w) {
        if (f[y][x] == '#') {
            tree_count += 1;
        } else if (f[y][x] == 'H') {
            last_house_y = y;
        } else {
            road_count += 1;
        }
    }
    int result = -1;
    vector<pair<uint64_t, char> > cur, prv;
    {
        array<char, max_w> conn;
        whole(fill, conn, -1);
        cur.emplace_back(pack(conn), 0);
    }
    repeat (y, h) {
        cur.swap(prv);
        cur.clear();
        int non_plain = 0;
        repeat (x, w) {
            if (f[y][x] != '.') {
                non_plain |= 1 << x;
            }
        }
        for (auto packed : prv) {
            state_t a = { unpack(packed.first), packed.second };
            repeat (flower, 1 << w) if (not (flower & non_plain)) {
                state_t b = append(a, f[y], flower);
                if (b.area == -1) {
                    // nop
                } else if (whole(count, a.conn, -1) != max_w and whole(count, b.conn, -1) == max_w) {
                    if (last_house_y <= y) {
                        setmax(result, road_count - b.area);
                    }
                } else {
                    cur.emplace_back(pack(b.conn), b.area);
                }
            }
        }
        whole(sort, cur);
        cur.erase(whole(unique, cur, [&](pair<uint64_t, char> const & a, pair<uint64_t, char> const & b) {
            return a.first == b.first;
        }), cur.end());
        if (last_house_y <= y) {
            for (auto packed : cur) if (is_connected(unpack(packed.first))) {
                setmax(result, road_count - packed.second);
            }
        }
        whole(sort, cur, [&](pair<uint64_t, char> const & a, pair<uint64_t, char> const & b) {
            return a.second < b.second;
        });
        cur.resize(min<int>(cur.size(), 1700)); // *MAGIC*
    }
    // output
    cout << result << endl;
    return 0;
}
```
