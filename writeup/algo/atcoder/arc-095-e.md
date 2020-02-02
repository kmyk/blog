---
layout: post
title: "AtCoder Regular Contest 095: E - Symmetric Grid"
date: 2018-12-07T02:18:56+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "optimization", "exhaustive-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc095/tasks/arc095_c" ]
---

## 解法

### 概要

適切に枝刈り全探索を書けば通る。
1点に注目し行と列をひとつ固定することを左上から中央へ向かって繰り返す。
このとき反対側の行と列も固定し、各行/各列に出現する数字の多重集合を持ってこれで枝刈り、さらに固定される位置の文字が単調増加するように枝刈り。
とても速い $$O(HW(H + W)H!W!)$$。
想定解も階乗が乗るので通るべくして通る非想定という感じ。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
template <typename T> ostream & operator << (ostream & out, vector<T> const & xs) { REP (i, int(xs.size()) - 1) out << xs[i] << ' '; if (not xs.empty()) out << xs.back(); return out; }

bool solve(int h, int w, vector<string> s) {
    // transpose
    if (h > w) {
        vector<string> t(w, string(h, '\0'));
        REP (y, h) REP (x, w) {
            t[x][y] = s[y][x];
        }
        swap(h, w);
        s = t;
    }
    assert (h <= w);

    // make the table from letters
    array<vector<pair<int, int> >, 26> lookup;
    REP (y, h) REP (x, w) {
        lookup[s[y][x] - 'a'].emplace_back(y, x);
    }

    auto row_compatible = vectors(h, h, bool());
    auto col_compatible = vectors(w, w, bool());
    REP (y1, h) REP (y2, h) {
        row_compatible[y1][y2] = (multiset<int>(ALL(s[y1])) == multiset<int>(ALL(s[y2])));
    }
    REP (x1, w) REP (x2, w) {
        multiset<int> ms1, ms2;
        REP (y, h) {
            ms1.insert(s[y][x1]);
            ms2.insert(s[y][x2]);
        }
        col_compatible[x1][x2] = (ms1 == ms2);
    }

    vector<int> row(h, -1);
    vector<int> col(w, -1);
    int used_row = 0;
    int used_col = 0;

    auto check_col = [&](int x) {
        assert (col[x] != -1 and col[w - x - 1] != -1);
        REP (y, h) if (row[y] != -1) {
            if (s[row[y]][col[x]] != s[row[h - y - 1]][col[w - x - 1]]) {
                return false;
            }
        }
        return true;
    };
    auto check_row = [&](int y) {
        assert (row[y] != -1 and row[h - y - 1] != -1);
        REP (x, w) if (col[x] != -1) {
            if (s[row[y]][col[x]] != s[row[h - y - 1]][col[w - x - 1]]) {
                return false;
            }
        }
        return true;
    };
    auto check = [&]() {
        REP (y, (h + 1) / 2) if (row[y] != -1) {
            if (not check_row(y)) {
                return false;
            }
        }
        return true;
    };

    // exhaustive search
    function<bool (int, char)> go = [&](int z, char last_c) {
        if (z < h - z - 1) {
            REP3 (c, last_c, 'z' + 1) {
                for (auto p1 : lookup[c - 'a']) {
                    int y1, x1; tie(y1, x1) = p1;
                    if (used_row & (1 << y1)) continue;
                    if (used_col & (1 << x1)) continue;
                    row[z] = y1;
                    col[z] = x1;
                    used_row ^= (1 << y1);
                    used_col ^= (1 << x1);
                    for (auto p2 : lookup[c - 'a']) {
                        int y2, x2; tie(y2, x2) = p2;
                        if (used_row & (1 << y2)) continue;
                        if (used_col & (1 << x2)) continue;
                        if (not row_compatible[y1][y2]) continue;
                        if (not col_compatible[x1][x2]) continue;
                        row[h - z - 1] = y2;
                        col[w - z - 1] = x2;
                        used_row ^= (1 << y2);
                        used_col ^= (1 << x2);
                        if (check_row(z) and check_col(z)) {
                            if (go(z + 1, c)) {
                                return true;
                            }
                        }
                        used_row ^= (1 << y2);
                        used_col ^= (1 << x2);
                        row[h - z - 1] = -1;
                        col[w - z - 1] = -1;
                    }
                    used_row ^= (1 << y1);
                    used_col ^= (1 << x1);
                    row[z] = -1;
                    col[z] = -1;
                }
            }

        } else if (used_row != ((1 << h) - 1)) {
            REP (y, h) if (not (used_row & (1 << y))) {
                row[h / 2] = y;
                used_row ^= (1 << y);
                if (go(z, last_c)) {
                    return true;
                }
                used_row ^= (1 << y);
                row[h / 2] = -1;
            }

        } else if (z < w - z - 1) {
            REP (x1, w) {
                char c = s[row[h / 2]][x1];
                if (used_col & (1 << x1)) continue;
                if (c < last_c) continue;
                col[z] = x1;
                used_col ^= (1 << x1);
                REP (x2, w) {
                    if (used_col & (1 << x2)) continue;
                    if (not col_compatible[x1][x2]) continue;
                    col[w - z - 1] = x2;
                    used_col ^= (1 << x2);
                    if (check_col(z)) {
                        if (go(z + 1, c)) {
                            return true;
                        }
                    }
                    used_col ^= (1 << x2);
                    col[w - z - 1] = -1;
                }
                used_col ^= (1 << x1);
                col[z] = -1;
            }

        } else if (used_col != ((1 << w) - 1)) {
            REP (x, w) if (not (used_col & (1 << x))) {
                col[w / 2] = x;
                used_col ^= (1 << x);
                if (go(z, last_c)) {
                    return true;
                }
                used_col ^= (1 << x);
                col[w / 2] = -1;
            }

        } else {
            if (check()) {
                return true;
            }
        }
        return false;
    };
    return go(0, 'a');
}

int main() {
    int h, w; cin >> h >> w;
    vector<string> s(h);
    REP (y, h) cin >> s[y];
    cout << (solve(h, w, s) ? "YES" : "NO") << endl;
    return 0;
}
```
