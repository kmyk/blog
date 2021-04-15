---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/world-codesprint-8-sams-puzzle/
  - /blog/2016/12/20/world-codesprint-8-sams-puzzle/
date: "2016-12-20T02:33:07+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/sams-puzzle" ]
---

# HackerRank World CodeSprint 8: Sam's Puzzle (Approximate)

I got $60.35$pts of $85$pts. In cases of $n = 30$, the $\max \\{ 0, \frac{g_a - g_b}{g\_{\mathrm{max}} - g_b} \\} \approx 0.45$. This is not bad.

I've got the $36$-th place in this contest and won the prizes.

## problem

$n \times n$の盤面$A$で、各マスに$1, 2, \dots, n^2$がそれぞれ配置されたものが与えられる。
盤面$A$に対しその評価値が定義されていて、座標の対$((y_1, x_1), (y_2, x_2))$で$y_1 \le y_2 \land x_1 \le x_2$かつ$y_1 = y_2 \lor x_1 = x_2$かつ$A(y_1, x_1) \lt A(y_2, x_2)$を満たすようなものの数がその値である。
盤面に対し回転操作$(y, x, k)$も定義されていて、左上を$(y, x)$とする$k \times k$の正方形部分を右に$90^{\circ}$回転させることができる。
この回転操作を$500$回以内の回数行い、評価値を最大化せよ。
最大評価値が構成できることは保証されており、これにどれだけ近付けられたかどうかの割合による滑らかな得点が得られる。

## solution

At first, move small numbers to left-upper places where there are no greater numbers up or left.
Move $0$ to the upper-left corner $(1, 1)$, $1$ to the $(1, 2)$ or $(2, 1)$, $3$ to $(1, 2)$, $(2, 1)$, $(1, 3)$ or $(3, 1)$, $\dots$.
This is analogies to the described process to generate the test cases.
Use dijkstra.

(I feel I should have try to move large numbers to right-bottom places too.)

The above method is good, but that leaves much time.
So you should do bruteforce search using the all of time limit $2.0$sec.

## implementation

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <tuple>
#include <functional>
#include <chrono>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= int(m); --(i))
typedef long long ll;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

const int inf = 1e9+7;
const int limit = 500;
int goodness(vector<vector<int> > const & f) {
    int n = f.size();
    int cnt = 0;
    repeat (y,n) repeat (xr,n) repeat (xl,xr) cnt += (f[y][xl] < f[y][xr]);
    repeat (x,n) repeat (yr,n) repeat (yl,yr) cnt += (f[yl][x] < f[yr][x]);
    return cnt;
}
vector<vector<int> > rotate(int y, int x, int k, vector<vector<int> > const & f) {
    vector<vector<int> > g = f;
    repeat (dy,k) repeat (dx,k) g[y+dx][x+k-dy-1] = f[y+dy][x+dx];
    return g;
}
pair<int, int> find_cell(vector<vector<int> > const & f, int k) {
    int n = f.size();
    repeat (y,n) repeat (x,n) if (f[y][x] == k) return { y, x };
    assert (false);
}
bool is_next_fixed(int y, int x, vector<vector<bool> > const & fixed) {
    return (y == 0 or fixed[y-1][x]) and (x == 0 or fixed[y][x-1]);
}

void solve_fast(int n, vector<vector<int> > & f, vector<tuple<int, int, int> > & result) {
    vector<vector<bool> > fixed = vectors(n, n, bool());
    vector<int> fixed_length(n);
    int next_fixed = 1;
    while (result.size() < limit*0.96 and next_fixed <= n*n) {
        int py, px; tie(py, px) = find_cell(f, next_fixed);
        if (is_next_fixed(py, px, fixed)) {
            fixed[py][px] = true;
            next_fixed += 1;
        } else {
            bool found = false;
            vector<vector<int> > dist = vectors(n, n, inf);
            vector<vector<tuple<int, int, int, int, int> > > path = vectors(n, n, tuple<int, int, int, int, int>());
            reversed_priority_queue<tuple<int, int, int> > que;
            dist[py][px] = 0;
            que.emplace(0, py, px);
            auto commit = [&](int y, int x) {
                deque<tuple<int, int, int> > acc;
                while (y != py or x != px) {
                    int ry, rx, rk; tie(y, x, ry, rx, rk) = path[y][x];
                    acc.emplace_front(ry, rx, rk);
                }
                if (result.size() + acc.size() > limit) return;
                for (auto it : acc) {
                    int ry, rx, rk; tie(ry, rx, rk) = it;
                    f = rotate(ry, rx, rk, f);
                    result.push_back(it);
                }
                found = true;
            };
            while (not que.empty()) {
                int z, y, x; tie(z, y, x) = que.top(); que.pop();
                if (is_next_fixed(y, x, fixed)) {
                    commit(y, x);
                    break;
                }
                auto push = [&](int ny, int nx, int ry, int rx, int rk) {
                    if (dist[ny][nx] != inf) return;
                    dist[ny][nx] = z+1;
                    path[ny][nx] = make_tuple(y, x, ry, rx, rk);
                    que.emplace(z+1, ny, nx);
                };
                for (int k = 2; y+k-1 <  n and x+k-1 <  n and not fixed[y    ][x    ]; ++ k) push(y,     x+k-1, y,     x,     k); // right
                for (int k = 2; y+k-1 <  n and x-k+1 >= 0 and not fixed[y    ][x-k+1]; ++ k) push(y+k-1, x,     y,     x-k+1, k); // down
                for (int k = 2; y-k+1 >= 0 and x+k-1 <  n and not fixed[y-k+1][x    ]; ++ k) push(y-k+1, x,     y-k+1, x,     k); // up
                for (int k = 2; y-k+1 >= 0 and x-k+1 >= 0 and not fixed[y-k+1][x-k+1]; ++ k) push(y,     x-k+1, y-k+1, x-k+1, k); // left
            }
            if (not found) break;
        }
    }
}

void solve_slow(int n, vector<vector<int> > & f, vector<tuple<int, int, int> > & result) {
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();
    while (result.size() < limit) {
        chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count() >= 1900) break;
        int best_y, best_x, best_k;
        int best = goodness(f);
        repeat (y,n) repeat (x,n) repeat_from_reverse (k,2,min(n-y,n-x)+1) {
            int z = goodness(rotate(y, x, k, f));
            if (best < z) {
                best_y = y;
                best_x = x;
                best_k = k;
                best   = z;
            }
        }
        if (best == goodness(f)) break;
        f = rotate(best_y, best_x, best_k, f);
        result.emplace_back(best_y, best_x, best_k);
    }
}

vector<tuple<int, int, int> > solve(int n, vector<vector<int> > f) {
    vector<tuple<int, int, int> > result;
    solve_fast(n, f, result);
    solve_slow(n, f, result);
    return result;
}

int main() {
    int n; cin >> n;
    vector<vector<int> > f = vectors(n, n, int());
    repeat (y,n) repeat (x,n) cin >> f[y][x];
    int gb = goodness(f);
    int gmax = n*n*(n-1);
    vector<tuple<int, int, int> > result = solve(n, f);
    cout << result.size() << endl;
    assert (result.size() <= 500);
    for (auto it : result) {
        int y, x, k; tie(y, x, k) = it;
        cout << y+1 << ' ' << x+1 << ' ' << k << endl;
        assert (0 <= y and y < n and 0 <= x and x < n and 1 <= k and max(y,x) + k <= n);
        f = rotate(y, x, k, f);
    }
    repeat (y,n) {
        repeat (x,n) cerr << (f[y][x] <= 9 ? " " : "") << f[y][x] << " ";
        cerr << endl;
    }
    cerr << "size: " << result.size() << endl;
    int ga = goodness(f);
    cerr << "points: " << ((ga - gb)/(double)(gmax - gb)) << endl;
    return 0;
}
```
