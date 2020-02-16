---
layout: post
alias: "/blog/2017/05/14/gcj-2017-round2-c/"
date: "2017-05-14T01:55:08+09:00"
tags: [ "competitive", "writeup", "gcj", "sat", "3-sat", "togasat" ]
"target_url": [ "https://code.google.com/codejam/contest/5314486/dashboard#s=p2" ]
---

# Google Code Jam 2017 Round 2: C. Beaming With Joy

``` c++
dir_t mirror(char c, dir_t d) {
    ...
            case RIGHT: return DOWN;
            case LEFT: return UP;
    ...
}
```

であるところを、

``` c++
            case RIGHT: return UP;
            case LEFT: return DOWN;
```

としてlargeを落としました。
Tシャツは増えたとはいえ、これがなかったらRound 3だったのでとても残念。

## solution

$3$-satにしてsolverに投げる。計算量はとりあえず$O(2^{HW})$。

変数を用意する: 砲台が水平であるかどうかを$v\_i$、ある点を光線が通っているかを$w\_{y,x}$とする。
点$(y, x)$を光線が通るような砲台の番号と向きを列挙し$x\_1, \dots, x\_k$として、項$\lnot (\lnot x\_1 \land \dots \land \lnot x\_k) \to \lnot w\_{y,x}$および項$w\_{y,x}$を制約式に追加する。
あとはこれを解けばよい。

実際は$2$-satで十分。ある点を通る光線が$3$つ以上あれば、砲台は破壊されないという制約に違反するため。$3$-satでも十分賢ければ内部で$O(HW)$ぐらいに落ちていそう。

## implementation

Togasatを利用した: <https://github.com/togatoga/Togasat> @ `00d8a82cbf2b91d36c990fb6e101e5d49357d96d`

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cassert>
#include "Solver.hpp"
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

enum dir_t { UP, DOWN, RIGHT, LEFT };
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
dir_t mirror(char c, dir_t d) {
    if (c == '/') {
        switch (d) {
            case UP: return RIGHT;
            case DOWN: return LEFT;
            case RIGHT: return UP;
            case LEFT: return DOWN;
        }
    } else if (c == '\\') {
        switch (d) {
            case UP: return LEFT;
            case DOWN: return RIGHT;
            case RIGHT: return DOWN;
            case LEFT: return UP;
        }
    }
    assert (false);
}

vector<string> solve(int h, int w, vector<string> const & s) {
    // analyze the field
    auto is_on_field = [&](int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; };
    vector<pair<int, int> > shooters;
    repeat (y,h) {
        repeat (x,w) {
            if (s[y][x] == '-' or s[y][x] == '|') {
                shooters.emplace_back(y, x);
            }
        }
    }
    function<bool (int, int, dir_t, vector<pair<int, int> > &)> shoot = [&](int y, int x, dir_t d, vector<pair<int, int> > & acc) {
        int ny = y + dy[d];
        int nx = x + dx[d];
        if (not is_on_field(ny, nx) or s[ny][nx] == '#') { // goal
            return true;
        } else if (s[ny][nx] == '.') {
            acc.emplace_back(ny, nx);
            return shoot(ny, nx, d, acc);
        } else if (s[ny][nx] == '/' or s[ny][nx] == '\\') {
            return shoot(ny, nx, mirror(s[ny][nx], d), acc);
        } else if (s[ny][nx] == '-' or s[ny][nx] == '|') {
            acc.clear();
            return false;
        } else {
            assert (false);
        }
    };
    vector<char> shooter_result(shooters.size(), '\0');
    auto used = vectors(h, w, bool());
    auto vars = vectors(h, w, vector<int>());
    repeat (i, shooters.size()) {
        int y, x; tie(y, x) = shooters[i];
        vector<pair<int, int> > a, b;
        bool is_hr = shoot(y, x, RIGHT, a) and shoot(y, x, LEFT, a);
        bool is_vr = shoot(y, x, UP, b) and shoot(y, x, DOWN, b);
        if (not is_hr and not is_vr) {
            return vector<string>(); // IMPOSSIBLE
        } else if (not is_hr or not is_vr) {
            shooter_result[i] = (is_hr ? '-' : '|');
            if (a.empty()) a.swap(b);
            for (auto it : a) {
                int ay, ax; tie(ay, ax) = it;
                used[ay][ax] = true;
            }
        } else {
            for (auto it : a) {
                int ay, ax; tie(ay, ax) = it;
                vars[ay][ax].push_back(+ (i+1));
            }
            for (auto it : b) {
                int by, bx; tie(by, bx) = it;
                vars[by][bx].push_back(- (i+1));
            }
        }
    }
    // sat
    togasat::Solver solver;
    auto var_at = [&](int y, int x) { return 1 + shooters.size() + y * h + x; };
    vector<pair<int, int> > cnf;
    repeat (i, shooters.size()) {
        int x = i+1;
        vector<int> tautology;
        tautology.push_back(+ x);
        tautology.push_back(- x);
        solver.addClause(tautology);
    }
    repeat (y,h) {
        repeat (x,w) if (s[y][x] == '.' and not used[y][x]) {
            vector<int> clause = vars[y][x];
            clause.push_back(- var_at(y, x));
            solver.addClause(clause);
            vector<int> assertion;
            assertion.push_back(var_at(y, x));
            assertion.push_back(var_at(y, x));
            solver.addClause(assertion);
        }
    }
    togasat::lbool status = solver.solve();
    if (status != 0) return vector<string>(); // IMPOSSIBLE
    repeat (i, shooters.size()) if (not shooter_result[i]) {
        shooter_result[i] = (solver.assigns[i] ? '|' : '-');
    }
    // result
    vector<string> result = s;
    repeat (i, shooters.size()) {
        int y, x; tie(y, x) = shooters[i];
        result[y][x] = shooter_result[i];
    }
    return result;
}

int main() {
    int t; cin >> t;
    repeat (x,t) {
        int h, w; cin >> h >> w;
        vector<string> s(h); repeat (y,h) cin >> s[y];
        vector<string> result;
        result = solve(h, w, s);
        cout << "Case #" << x+1 << ": " << (result.empty() ? "IMPOSSIBLE" : "POSSIBLE") << endl;
        if (not result.empty()) {
            repeat (y,h) cout << result[y] << endl;
        }
    }
    return 0;
}
```
