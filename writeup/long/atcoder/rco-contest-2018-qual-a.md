---
layout: post
redirect_from:
  - /blog/2018/02/13/rco-contest-2018-qual-a/
date: "2018-02-13T15:09:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "rco-contest", "marathon-match", "beam-search" ]
"target_url": [ "https://rco-contest-2018-qual.contest.atcoder.jp/tasks/rco_contest_2018_qual_a" ]
---

# 第2回 RCO日本橋ハーフマラソン 予選: A - ゲーム実況者Xの挑戦

A問題に限れば$1$位だった。全体では$3$位。
いつもの勝ちパターン「とりあえずで典型を実装したらなぜか$1$位でしかもそのまま逃げ切れてしまう」を引いた。

メモ: <https://togetter.com/li/1198403>

## solution

$K$マップ固定して普通にビームサーチするだけ (290000点)

-   ビームサーチを使う
    -   貪欲山登りとかよりは自明に良い
    -   評価関数は単にコインの数
    -   全部生き残るようにする
-   ($M$マップ全部使うのではなくて) $K$マップ固定
    -   探索過程の評価関数が最終的な評価関数に近いものになる
    -   全員死なない移動の種類が増える
    -   $O(M)$が$O(K)$に落ちる
    -   マップはランダム生成なのでどれもたいして変わらない
    -   罠が少ないマップを選ぶのが良さそう (やってない)

なお元々は「$1$点マップだけに絞ってそのマップのコインを全部取れば確実に$2000$点だなあ、でも厳密な実装面倒だしビームサーチでいいや」という流れから書いたので、まったくの脳死ビームサーチではない。

## implementation

<https://rco-contest-2018-qual.contest.atcoder.jp/submissions/2087422>

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

const char cmd[] = { 'U', 'D', 'R', 'L' };
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };

constexpr int n = 100;
constexpr int k = 8;
constexpr int h = 50;
constexpr int w = 50;
constexpr int t = 2500;
bool is_on_field(int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; }

struct state_t {
    bitset<h * w> visited;
    size_t hash_visited;
    int y, x;
    int score;
    int index;
};
inline bool is_trapped(state_t const & a, array<array<char, w>, h> const & f) {
    return f[a.y][a.x] == 'x';
}
bool is_trapped_if_move(int dir, state_t const & a, array<array<char, w>, h> const & f) {
    int ny = a.y + dy[dir];
    int nx = a.x + dx[dir];
    return f[ny][nx] == 'x';
}
void exec_move(int dir, state_t & a, array<array<char, w>, h> const & f) {
    if (is_trapped(a, f)) return;
    int ny = a.y + dy[dir];
    int nx = a.x + dx[dir];
    if (f[ny][nx] != '#') {
        a.y = ny;
        a.x = nx;
        if (f[ny][nx] == 'o' and not a.visited[ny * w + nx]) {
            a.visited[ny * w + nx] = true;
            a.hash_visited = hash<bitset<h * w> >()(a.visited);
            a.score += 1;
        }
    }
}

template <typename T>
struct single_list {
    T value;
    shared_ptr<single_list<T> > next;
};
template <int m>
struct beam_state {
    shared_ptr<array<state_t, m> > state;
    size_t hash_state;
    int score;
    shared_ptr<single_list<int> > cmds;
};

template <int m, class RandomGenerator>
vector<int> generate_tour(array<array<array<char, w>, h>, m> const & f, array<int, m> initial_y, array<int, m> initial_x, RandomGenerator & gen) {
    vector<beam_state<m> > cur, prv; {
        beam_state<m> init = {};
        init.state = make_shared<array<state_t, m> >();
        init.score = 0;
        init.hash_state = -1;
        REP (i, m) {
            (*init.state)[i].visited.reset();
            (*init.state)[i].hash_visited = hash<bitset<h * w> >()((*init.state)[i].visited);
            (*init.state)[i].y = initial_y[i];
            (*init.state)[i].x = initial_x[i];
            (*init.state)[i].score = 0;
        }
        init.cmds = nullptr;
        cur.push_back(init);
    }
    REP (iteration, t) {
        cur.swap(prv);
        cur.clear();
        for (auto a : prv) {
            REP (dir, 4) {
                bool is_trapped = false;
                REP (i, m) {
                    if (is_trapped_if_move(dir, (*a.state)[i], f[i])) {
                        is_trapped = true;
                        break;
                    }
                }
                if (is_trapped) continue;
                beam_state<m> b = {};
                b.state = make_shared<array<state_t, m> >(*a.state);
                REP (i, m) {
                    exec_move(dir, (*b.state)[i], f[i]);
                    b.score += (*b.state)[i].score;
                    b.hash_state ^= hash<size_t>()((*b.state)[i].hash_visited ^ ((*b.state)[i].y << 16) ^ (*b.state)[i].x);
                }
                b.cmds = make_shared<single_list<int> >((single_list<int>) { dir, a.cmds });
                cur.emplace_back(b);
            }
        }
        int size = min<int>(100, cur.size());
        partial_sort(cur.begin(), cur.begin() + size, cur.end(), [&](beam_state<m> const & a, beam_state<m> const & b) {
            return a.score > b.score;
        });
        cur.resize(size);
        sort(ALL(cur), [&](beam_state<m> const & a, beam_state<m> const & b) {
            return a.hash_state < b.hash_state;
        });
        cur.erase(unique(ALL(cur), [&](beam_state<m> const & a, beam_state<m> const & b) {
            return a.hash_state == b.hash_state;
        }), cur.end());
    }
    auto it = max_element(ALL(cur), [&](beam_state<m> const & a, beam_state<m> const & b) {
        return a.score > b.score;
    })->cmds;
    vector<int> cmds;
    while (it) {
        cmds.push_back(it->value);
        it = it->next;
    }
    reverse(ALL(cmds));
    return cmds;
}

int main() {
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();

    // input
    { string s; getline(cin, s); }
    vector<array<array<char, w>, h> > f(n);
    vector<int> start_y(n);
    vector<int> start_x(n);
    REP (i, n) {
        REP (y, h) REP (x, w) {
            cin >> f[i][y][x];
            if (f[i][y][x] == '@') {
                start_y[i] = y;
                start_x[i] = x;
            }
        }
    }

    // solve
    int highscore = -1;
    array<int, k> result_maps;
    string result_commands;
    default_random_engine gen;
    for (int iteration = 0; ; ++ iteration) {
        chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count() >= 3500) break;

        vector<int> dirs; {
            constexpr int m = 8;
            vector<int> selected;
            while (selected.size() < m) {
                int j = uniform_int_distribution<int>(0, n - 1)(gen);
                if (not count(ALL(selected), j)) {
                    selected.push_back(j);
                }
            }
            array<array<array<char, w>, h>, m> fs;
            array<int, m> start_ys;
            array<int, m> start_xs;
            REP (i, m) {
                fs[i] = f[selected[i]];
                start_ys[i] = start_y[selected[i]];
                start_xs[i] = start_x[selected[i]];
            }
            dirs = generate_tour<m>(fs, start_ys, start_xs, gen);
        }

        vector<state_t> state(n);
        REP (i, n) {
            state[i].visited.reset();
            state[i].index = i;
            state[i].y = start_y[i];
            state[i].x = start_x[i];
            state[i].score = 0;
        }
        string commands;
        for (int dir : dirs) {
            commands += cmd[dir];
            REP (i, n) {
                exec_move(dir, state[i], f[i]);
            }
        }
        sort(ALL(state), [&](state_t const & a, state_t const & b) {
                return a.score > b.score;
                });
        int score = 0;
        REP (i, k) {
            score += state[i].score;
        }
        if (highscore < score) {
            highscore = score;
            REP (i, k) {
                result_maps[i] = state[i].index;
            }
            result_commands = commands;
        }
    }

    // output
    REP (i, k) {
        if (i) cout << ' ';
        cout << result_maps[i];
    }
    cout << endl;
    cout << result_commands << endl;
    return 0;
}
```
