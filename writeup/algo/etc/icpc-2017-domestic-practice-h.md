---
layout: post
alias: "/blog/2017/07/02/icpc-2017-domestic-practice-h/"
date: "2017-07-02T21:12:54+09:00"
title: "ACM-ICPC 2017 模擬国内予選: H. Big Maze"
tags: [ "competitive", "writeup", "aoj", "icpc-domestic", "dp", "frontier" ]
---

A B C Hの$4$完だった。Dが最後までバグっていたので全体$33$位。だめ。
問題に傾斜付けてくれ頼む。

## solution

動的計画法。(幾何とかと比べれば)実装は軽い。union-find木を使って$O(MN^3\alpha(N))$。

ブロックの順序は固定なので左から順に決定していけばよい。
困難はサンプルの$4$つ目のような戻る処理。
しかしこれは右端における接続関係に関する情報を全て残せば対処でき、状態数は多めに見ても$N^2$で抑えられるので間に合う。

残すべき情報は右端での接続情報。
例えば下図のような状態であれば、次の$2$つの情報に要約できる。

-   $1$行目は左端に繋がっている
-   $3$行目と$5$行目は繋がっている

```
..........
##########
##........
##.#######
##........
```

例えば$-1$は壁で同じ非負整数同士は繋がっており$0$は左端にも繋がっているとして、上の例における左端は$(0, -1, 1, -1, 1)$という列で表現できる。
このようなことはそのまま実装できる。union-find木を使うと楽。


## implementation

``` c++
#include <algorithm>
#include <functional>
#include <iostream>
#include <map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
bool is_on_field(int y, int x, int h, int w) { return 0 <= y and y < h and 0 <= x and x < w; }

struct disjoint_sets {
    vector<int> data;
    disjoint_sets() = default;
    explicit disjoint_sets(size_t n) : data(n, -1) {}
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

vector<string> rotate(vector<string> const & maze) {
    int n = maze.size();
    vector<string> rotated_maze = maze;
    repeat (y, n) {
        repeat (x, n) {
            rotated_maze[n - x - 1][y] = maze[y][x];
        }
    }
    return rotated_maze;
}

pair<vector<int>, vector<int> > summarize(vector<string> const & maze) {
    int n = maze.size();
    vector<int> l(n, -1);
    vector<int> r(n, -1);
    auto used = vectors(n, n, bool());
    function<void (int, int, int)> dfs = [&](int y, int x, int color) {
        used[y][x] = true;
        if (x == 0) l[y] = color;
        if (x == n - 1) r[y] = color;
        repeat (i, 4) {
            int ny = y + dy[i];
            int nx = x + dx[i];
            if (not is_on_field(ny, nx, n, n)) continue;
            if (maze[ny][nx] == '#') continue;
            if (not used[ny][nx]) {
                dfs(ny, nx, color);
            }
        }
    };
    int color = 0;
    repeat (y, n) {
        if (maze[y][0] == '.' and not used[y][0]) {
            dfs(y, 0, color);
            ++ color;
        }
        if (maze[y][n - 1] == '.' and not used[y][n - 1]) {
            dfs(y, n - 1, color);
            ++ color;
        }
    }
    return make_pair(l, r);
}

vector<int> append(vector<int> const & a, vector<int> const & bl, vector<int> const & br) {
    int n = a.size();
    disjoint_sets ds(2 * n);
    repeat (y, n) {
        if (a[y] != -1 and bl[y] != -1) {
            ds.union_sets(a[y], bl[y] + n);
        }
    }
    vector<int> c(n, -1);
    repeat (y, n) {
        if (br[y] != -1) {
            c[y] = ds.find_root(br[y] + n);
            if (ds.is_same(0, c[y])) {
                c[y] = 0;
            }
        }
    }
    return c;
}

vector<int> normalize(vector<int> const & a) {
    int n = a.size();
    vector<int> b(n, -1);
    map<int, int> f;
    bool is_connected = false;
    repeat (y, n) {
        if (a[y] == -1) {
            // nop
        } else if (a[y] == 0) {
            b[y] = 0;
            is_connected = true;
        } else {
            if (f.count(a[y])) {
                b[y] = f[a[y]];
            } else {
                int next_color = f.size() + 1;
                b[y] = f[a[y]] = next_color;
            }
        }
    }
    if (not is_connected) return vector<int>();
    return b;
}

int main() {
    while (true) {
        int n, m; cin >> n >> m;
        if (n == 0 and m == 0) break;
        vector<vector<int> > cur, prv;
        cur.emplace_back(n, 0);
        repeat (i, m) {
            cur.swap(prv);
            cur.clear();
            vector<string> maze(n);
            repeat (y, n) cin >> maze[y];
            repeat (d, 4) {
                auto b = summarize(maze);
                for (auto const & a : prv) {
                    auto c = append(a, b.first, b.second);
                    c = normalize(c);
                    if (not c.empty()) {
                        cur.push_back(c);
                    }
                }
                maze = rotate(maze);
            }
            whole(sort, cur);
            cur.erase(whole(unique, cur), cur.end());
        }
        cout << (cur.empty() ? "No" : "Yes") << endl;
    }
    return 0;
}
```
