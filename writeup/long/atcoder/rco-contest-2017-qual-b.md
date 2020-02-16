---
layout: post
alias: "/blog/2017/03/05/rco-contest-2017-qual-b/"
date: "2017-03-05T01:50:07+09:00"
tags: [ "competitive", "writeup", "atcoder", "rco-contest", "half-marathon", "random", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/rco-contest-2017-qual/tasks/rco_contest_2017_qual_b" ]
---

# RCO presents 日本橋ハーフマラソン 予選: B - Food Collector

## solution

貪欲。$17586$点。本番時B問題内で$15$位。

貪欲は、最も近い位置の餌へ貪欲に移動するのを繰り返すだけ。
ただし餌を食べたときの点数は負になりうるので、それだけは避けるようにする(重要)。

時間がなかったので乱択とかそういうのは間に合わなかった。
滑り込みで提出したやつはバグが残っていた。
TLE$10$秒なのに実行時間は$0.045$秒しか使ってないのもったいない。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <array>
#include <queue>
#include <tuple>
#include <random>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
const char dc[] = "UDRL";
constexpr int h = 50;
constexpr int w = 50;
constexpr int k = 2500;
bool is_on_field(int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; }
struct point_t {
    int y, x;
};
struct food_t {
    int y, x, score, decr;
};
constexpr int inf = 1e9+7;
 
vector<vector<int> > compute_dist(int start_y, int start_x, array<array<bool,h>,w> const & is_wall, vector<food_t> const & foods) {
    auto dist = vectors(foods.size()+1, foods.size()+1, inf); // +1: for the start point
    repeat (i,foods.size()+1) {
        int sy = i == foods.size() ? start_y : foods[i].y;
        int sx = i == foods.size() ? start_x : foods[i].x;
        auto used = vectors(h, w, int(h*w));
        queue<point_t> que;
        used[sy][sx] = 0;
        que.push((point_t) { sy, sx });
        while (not que.empty()) {
            int y = que.front().y;
            int x = que.front().x;
            que.pop();
            repeat (j,4) {
                int ny = y + dy[j];
                int nx = x + dx[j];
                if (not is_on_field(ny, nx)) continue;
                if (is_wall[ny][nx]) continue;
                if (used[ny][nx] <= used[y][x] + 1) continue;
                used[ny][nx] = used[y][x] + 1;
                que.push((point_t) { ny, nx });
            }
        }
        repeat (j,foods.size()+1) {
            int gy = j == foods.size() ? start_y : foods[j].y;
            int gx = j == foods.size() ? start_x : foods[j].x;
            dist[i][j] = used[gy][gx];
        }
    }
    return dist;
}
 
string reconstruct_movement(vector<int> const & indices, int start_y, int start_x, array<array<bool,h>,w> const & is_wall, vector<food_t> const & foods) {
    string movement;
    repeat (nxt, int(indices.size())) {
        int cur = nxt-1;
        int sy = cur == -1 ? start_y : foods[indices[cur]].y;
        int sx = cur == -1 ? start_x : foods[indices[cur]].x;
        int gy = foods[indices[nxt]].y;
        int gx = foods[indices[nxt]].x;
        auto used = vectors(h, w, int(h*w));
        queue<point_t> que;
        used[gy][gx] = 0;
        que.push((point_t) { gy, gx });
        while (not que.empty()) {
            int y = que.front().y;
            int x = que.front().x;
            que.pop();
            if (y == sy and x == sx) break;
            repeat (j,4) {
                int ny = y + dy[j];
                int nx = x + dx[j];
                if (not is_on_field(ny, nx)) continue;
                if (is_wall[ny][nx]) continue;
                if (used[ny][nx] <= used[y][x] + 1) continue;
                used[ny][nx] = used[y][x] + 1;
                que.push((point_t) { ny, nx });
            }
        }
        int y = sy;
        int x = sx;
        while (used[y][x]) {
            repeat (i,4) {
                int py = y + dy[i];
                int px = x + dx[i];
                if (not is_on_field(py, px)) continue;
                if (used[py][px] >= used[y][x]) continue;
                movement += dc[i];
                y = py;
                x = px;
                break;
            }
        }
    }
    return movement;
}
 
int food_score(food_t const & food, int t) {
    return food.score - t * food.decr;
}
 
template <class Generator>
tuple<vector<int>,ll> solve_1(vector<vector<int> > const & dist, int start_y, int start_x, array<array<bool,h>,w> const & is_wall, vector<food_t> const & foods, Generator & gen) {
    vector<int> indices; // of visited foods
    ll score = 0;
    int t = 0;
    int cur = foods.size(); // start point
    vector<int> remaining(foods.size());
    whole(iota, remaining, 0);
    while (not remaining.empty() and t < k) {
        int nxt = -1;
        for (int i : remaining) {
            if (nxt == -1 or dist[cur][i] < dist[cur][nxt]) {
                if (food_score(foods[i], t + dist[cur][i] - 1) > 0) {
                    nxt = i;
                }
            }
        }
        if (nxt == -1) break;
        indices.push_back(nxt);
        remaining.erase(whole(remove, remaining, nxt), remaining.end());
        t += dist[cur][nxt];
        score += foods[nxt].score - (t-1) * foods[nxt].decr;
        cur = nxt;
    }
    while (t > k) {
        int nxt = indices.back();
        indices.pop_back();
        int cur = indices.back();
        t -= dist[cur][nxt];
    }
    return make_tuple(indices, score);
}
 
string solve(int start_y, int start_x, array<array<bool,h>,w> const & is_wall, vector<food_t> const & foods) {
    random_device device;
    default_random_engine gen(device());
    auto dist = compute_dist(start_y, start_x, is_wall, foods);
    vector<int> result;
    ll best_score = -1;
    vector<int> indices; ll score; tie(indices, score) = solve_1(dist, start_y, start_x, is_wall, foods, gen);
    if (best_score < score) {
        best_score = score;
        result = indices;
    }
    return reconstruct_movement(result, start_y, start_x, is_wall, foods);
}
 
int main() {
    // input
    { // fixed params
        int a_h, a_w, a_k; cin >> a_h >> a_w >> a_k;
        assert (a_h == h and a_w == w and a_k == k);
    }
    int start_y, start_x;
    cin >> start_y >> start_x;
    -- start_y; -- start_x;
    array<array<bool,h>,w> is_wall;
    repeat (y,h) repeat (x,w) {
        char c; cin >> c;
        is_wall[y][x] = (c == '#');
    }
    vector<food_t> foods; {
        int n; cin >> n;
        foods.resize(n);
        repeat (i,n) {
            auto & a = foods[i];
            cin >> a.y >> a.x >> a.score >> a.decr;
            -- a.y; -- a.x;
        }
    }
    // solve
    string result = solve(start_y, start_x, is_wall, foods);
    // output
    assert (result.size() <= k);
    while (result.size() < k) result += '-';
    cout << result << endl;
    return 0;
}
```
