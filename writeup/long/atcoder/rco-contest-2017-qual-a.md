---
layout: post
redirect_from:
  - /writeup/long/atcoder/rco-contest-2017-qual-a/
  - /blog/2017/03/05/rco-contest-2017-qual-a/
date: "2017-03-05T01:50:06+09:00"
tags: [ "competitive", "writeup", "atcoder", "rco-contest", "half-marathon", "random", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/rco-contest-2017-qual/tasks/rco_contest_2017_qual_a" ]
---

# RCO presents 日本橋ハーフマラソン 予選: A - Multiple Pieces


-   $2$問もあってtester/visualizerまであってとても豪華だった。またやってほしい
    -   しかし豪華すぎて時間がまったく足りなかった
-   問題別だと両方とも$15$位だったが、総合だと$9$位でけっこう良い
    -   もう$1$戦できるので嬉しい
-   面白かったのでまたやってほしい

## solution

貪欲 (+ 乱択 繰り返し)。$909828$点。本番時A問題内で$15$位。

貪欲は、始点とするマスをひとつ決めて隣接するマスを数字の大きい順にくっつけていく。
これを盤面が埋まるまで繰り返す。

始点するマスの決め方は、そのマスの値の大きい順にするとよい。
まず$9$と書かれたマスを集めてきてその中でランダムな順で使用、次に$8$と書かれたマスを$\dots$、とした。
マスをくっつけていく部分は、乱数で揺らしつつ適当にした。

乱択解は$5$分おきに忘れず提出するべきであるが、この用途に自動提出器はとても便利: <https://github.com/kmyk/online-judge-tools>

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <queue>
#include <tuple>
#include <random>
#include <chrono>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
constexpr int h = 50;
constexpr int w = 50;
constexpr int k = 8;
bool is_on_field(int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; }
struct point_t { int y, x; };
bool operator < (point_t a, point_t b) { return make_pair(a.y, a.x) < make_pair(b.y, b.x); }

template <class Generator>
vector<point_t> solve_piece(int y, int x, array<array<bool,w>,h> & used, array<array<int8_t,w>,h> const & f, Generator & gen) {
    if (used[y][x]) return vector<point_t>();
    uniform_real_distribution<double> dist(0.8, 1.2);
    vector<point_t> result;
    ll best_score = 0;
    repeat (iteration,30) {
        vector<point_t> piece;
        ll score = 1;
        array<array<bool,w>,h> pushed = {};
        priority_queue<tuple<double, point_t> > que;
        que.emplace(f[y][x], (point_t) { y, x });
        while (not que.empty() and piece.size() < k) {
            int y = get<1>(que.top()).y;
            int x = get<1>(que.top()).x;
            que.pop();
            piece.push_back((point_t) { y, x });
            used[y][x] = true;
            score *= f[y][x];
            repeat (i,4) {
                int ny = y + dy[i];
                int nx = x + dx[i];
                if (not is_on_field(ny, nx)) continue;
                if (used[ny][nx]) continue;
                if (pushed[ny][nx]) continue;
                double value = sqrt(f[ny][nx]) * dist(gen);
                que.emplace(value, (point_t) { ny, nx });
                pushed[ny][nx] = true;
            }
        }
        if (piece.size() == k) {
            if (best_score < score) {
                best_score = score;
                result = piece;
            }
            for (auto p : piece) {
                used[p.y][p.x] = false; // rewind
            }
        } else {
            // an isolated components with size < K
            // used is not rewinded
            return vector<point_t>();
        }
    }
    for (auto p : result) {
        used[p.y][p.x] = true; // commit
    }
    return result;
}

template <class T>
ll compute_score(T const & piece, array<array<int8_t,w>,h> const & f) {
    ll acc = 1;
    for (auto p : piece) acc *= f[p.y][p.x];
    return acc;
}

template <class Generator>
tuple<vector<array<point_t,k> >,ll> solve_1(array<array<int8_t,w>,h> const & f, Generator & gen) {
    array<array<bool,w>,h> used = {};
    repeat (y,h) repeat (x,w) {
        if (f[y][x] == 0) used[y][x] = true;
    }
    vector<array<point_t,k> > pieces;
    ll score = 0;
    repeat_reverse (base,10) {
        vector<point_t> ps;
        repeat (y,h) repeat (x,w) if (not used[y][x]) {
            if (f[y][x] == base) {
                ps.push_back((point_t) { y, x });
            }
        }
        whole(shuffle, ps, gen);
        for (auto p : ps) {
            vector<point_t> piece = solve_piece(p.y, p.x, used, f, gen);
            if (piece.empty()) continue;
            array<point_t,k> a;
            whole(move, piece, a.begin());
            pieces.push_back(a);
            score += compute_score(piece, f);
        }
    }
    return make_tuple(pieces, score);
}

vector<array<point_t,k> > solve(array<array<int8_t,w>,h> const & f) {
    random_device device;
    default_random_engine gen(device());
    vector<array<point_t,k> > result;
    ll best_score = -1;
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();
    while (true) {
        vector<array<point_t,k> > pieces; ll score; tie(pieces, score) = solve_1(f, gen);
        if (best_score < score) {
            best_score = score;
            result = pieces;
        }
        chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count() >= 9.5 * 1000) break;
    }
    return result;
}

int main() {
    // input
    { // fixed params
        int a_h, a_w, a_k; cin >> a_h >> a_w >> a_k;
        assert (a_h == h and a_w == w and a_k == k);
    }
    array<array<int8_t,w>,h> f;
    repeat (y,h) repeat (x,w) {
        char c; cin >> c;
        assert ('0' <= c and c <= '9');
        f[y][x] = c - '0';
    }
    // solve
    vector<array<point_t,k> > result = solve(f);
    // output
    cout << result.size() << endl;
    for (const auto & piece : result) {
        for (auto p : piece) {
            cout << p.y+1 << ' ' << p.x+1 << endl;
        }
    }
    return 0;
}
```
