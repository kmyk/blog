---
layout: post
alias: "/blog/2017/12/25/utpc2011-d/"
title: "東京大学プログラミングコンテスト2011: D. 停止問題"
date: "2017-12-25T19:10:43+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj", "befunge", "memoization" ]
---

-   <http://www.utpc.jp/2011/problems/defunge.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_4>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2262>

問題設定好き。

## solution

全状態空間をそのままメモ化探索。`?`の場合は$4$通りに分岐。実行の向きの種類数$D = 4$とメモリの取り得る値の種類数$M = 16$として$O(RCDM)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

const int dy[] = { 0, 1, 0, -1 };
const int dx[] = { 1, 0, -1, 0 };
int main() {
    // input
    int h, w; cin >> h >> w;
    vector<string> code(h);
    REP (y, h) cin >> code[y];
    // solve
    auto used = vectors(h, w, array<bitset<16>, 4>());
    function<bool (int, int, int, int)> go = [&](int y, int x, int dir, int mem) {
        y = (y + h) % h;
        x = (x + w) % w;
        if (used[y][x][dir][mem]) return false;
        used[y][x][dir][mem] = true;
        switch (code[y][x]) {
            case '<': dir = 2; break;
            case '>': dir = 0; break;
            case '^': dir = 3; break;
            case 'v': dir = 1; break;
            case '_': dir = (mem ? 2 : 0); break;
            case '|': dir = (mem ? 3 : 1); break;
            case '?': {
                REP (dir, 4) {
                    if (go(y + dy[dir], x + dx[dir], dir, mem)) {
                        return true;
                    }
                }
                return false;
            }
            case '.': break;
            case '@': return true;
            case '+': mem = (mem +  1) % 16; break;
            case '-': mem = (mem + 15) % 16; break;
            default: assert (isdigit(code[y][x])); mem = code[y][x] - '0'; break;
        }
        return go(y + dy[dir], x + dx[dir], dir, mem);
    };
    bool halt = go(0, 0, 0, 0);
    // output
    cout << (halt ? "YES" : "NO") << endl;
    return 0;
}
```
