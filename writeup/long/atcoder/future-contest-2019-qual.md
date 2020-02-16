---
layout: post
date: 2018-11-10T22:40:36+09:00
edited: 2018-11-19T22:00:00+09:00
tags: [ "competitive", "writeup", "atcoder", "half-marathon", "simulated-annealing" ]
"target_url": [ "https://beta.atcoder.jp/contests/future-contest-2019-qual/tasks/future_contest_2019_qual_a" ]
---

# HACK TO THE FUTURE 2019予選: A - ばらばらロボット


## 解法

### 概要

とりあえず焼き鈍しをしてひたすら高速化をした。
AtCoderなので天才解法の存在を疑いたくなるが、典型と実装をすべてきっちりやれば勝てる系の教育的な問題だった。

### 詳細

基本は焼き鈍し。
特にベースとなるのは、ランダムに選んだマスをランダムなマス `.` `#` `D` `T` `L` `R` で置き換えてみてロボットを走らせスコアが改善すれば採用するというもの。

近傍にはマス `.` `L` `R` のみを使った。
マス `#` を使うのは悪手である。ロボットが停止できるマスが減ると同じマスで止まって点数が減りやすくなるし、上を通過するロボットすべてと干渉するので変化が大きすぎる。
マス `D` `T` を使うのも同様にあまりよくない。命令 `S` `L` `R` のすべてに作用するためである。
マス `L` `R` はそれぞれ命令 `R` のみ `L` のみにしか作用しないので、これらだけを使うとよい。

差分更新による高速化をひたすらした。
時間を10倍ぐらいにして実行して山を登りきれているかの確認をしたところ、まったく登りきれてないことが分かったためである。
十分な時間があれば 140000点 に到達しうるだろうため、高速化勝負であると判断した。
実装は面倒だったが、コンテストは$8$時間あるので余裕を持って実装ができた。

まず愚直にロボットを走らせると$1$体あたり $O(L)$ で全体で $O(NL)$ かかる。
変更するのは1マスだけなので、そのマスを通るロボット$n$体についてのみ計算し修正すればよい。
これを事前に列挙しておけば $O(nL)$ に落ちる。
さらにそのマスを通る時刻$t$やその時の向きなどを記録しておけば、マスに到着してからの残りの$l = L - t$命令だけ処理することができ $O(nl)$ となる。
マス `#` `D` `T` はまったく使わないとしておけば、修正対象のロボットは「そのマスの上で `L` `R` 命令を実行するロボット」のみにできてさらに速くなる。
各マスごとに「そのマスを修正したときに実行することになるロボットの命令数」は同様に計算できるので、これを持っておき小さいものを優先的に試すのもいくらか効果があった。

この他に、盤面の形の工夫をした。
思い付くものをすべて試すと「盤面中央に `D` で縦線を引く」がうまくいったのでこれを採用した。
つまり下の図のような形を焼き鈍しの初期盤面とした。
「ロボットを足止めして命令を消費させ $L$ を小さくする」「ロボットを分断して個別に改善できるようにする」のふたつの目的を同時に達成できるためだろう。
一方でそれ以外の「`#` で色々な形の柵を作る」「`T` で高速に移動させ散らばらせる」などはどれも失敗だった。

```
#########
#.......#
#...D...#
#...D...#
#...D...#
#...D...#
#...D...#
#.......#
#########
```

ここまでを実装し運の良さで殴ると 134019点 が取れて1位で終了した。
ループの回数は手元で$60000 \sim 120000$回ほど。

ただし感想戦にてさらにここから改善点がいくつかあることが分かった。
ひとつは「`example_01.txt` を手元で数時間回した結果を埋め込む」こと。
ひとつは「命令列を事前に圧縮」すること。
例えば命令中に `LLL` という部分文字列があればこれを `R` で置き換えてよいなどである。
実際にはこれは嘘でもう少し丁寧にやる必要があるが、いずれにせよ命令列が短くなるので処理が速くなる。
もうひとつは「スコア悪化量が大きそうなら計算を途中で打ち切る」こと。
これも明らかに速くなる。
そして「初期盤面を `.` でなく `L` で埋める」こと。
試してみたところこれだけでなぜか点数が 800点 ほど上がった。
これがなぜかはまだあまり理解できていない。
次のような議論はあったことだけメモしておく。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr"><a href="https://twitter.com/hashtag/HTTF?src=hash&amp;ref_src=twsrc%5Etfw">#HTTF</a> 床をLで埋めたほうがよい理由が解明できた。<br>同じマス同じ向きのロボが2台あって、次の命令がそれぞれL、Rだったとする。このとき床が . だとこの2台は分岐し、床がLだと分岐しない。Lで埋めると分岐や合流が少なくなり各マスで旋回するロボ数が平均的に少なくなる。続く</p>&mdash; hakomo (@hakomof) <a href="https://twitter.com/hakomof/status/1061590504469450752?ref_src=twsrc%5Etfw">2018年11月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


## メモ

-   1位を取った AtCoderの順位表の上で1位は始めて かなりうれしい
-   本戦はICPCのHanoi遠征に衝突していて出場不能 ちなみに新卒枠でもあった
-   「初期盤面 `L` で埋める」はいいとしても「命令列を事前に圧縮」に気付けなかったのは反省したい

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">142k解の様子です <a href="https://twitter.com/hashtag/HTTF?src=hash&amp;ref_src=twsrc%5Etfw">#HTTF</a> <a href="https://t.co/27zeRh9pfe">pic.twitter.com/27zeRh9pfe</a></p>&mdash; not (@not_522) <a href="https://twitter.com/not_522/status/1063053243633127424?ref_src=twsrc%5Etfw">2018年11月15日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## 実装

### 本番 134019点

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= (int)(m); -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

class xor_shift_128 {
public:
    typedef uint32_t result_type;
    xor_shift_128(uint32_t seed = 42) {
        set_seed(seed);
    }
    void set_seed(uint32_t seed) {
        a = seed = 1812433253u * (seed ^ (seed >> 30));
        b = seed = 1812433253u * (seed ^ (seed >> 30)) + 1;
        c = seed = 1812433253u * (seed ^ (seed >> 30)) + 2;
        d = seed = 1812433253u * (seed ^ (seed >> 30)) + 3;
    }
    uint32_t operator() () {
        uint32_t t = (a ^ (a << 11));
        a = b; b = c; c = d;
        return d = (d ^ (d >> 19)) ^ (t ^ (t >> 8));
    }
    static constexpr uint32_t max() { return numeric_limits<result_type>::max(); }
    static constexpr uint32_t min() { return numeric_limits<result_type>::min(); }
private:
    uint32_t a, b, c, d;
};

constexpr int N = 500;
constexpr int M = 29;
constexpr int L = 300;

constexpr ll TIME_LIMIT = 3000;  // msec

enum direction_t : int8_t {
    RIGHT, UP, LEFT, DOWN
};
direction_t rotate_left (direction_t dir) { return (direction_t)(((int)dir + 1) % 4); }
direction_t rotate_right(direction_t dir) { return (direction_t)(((int)dir + 3) % 4); }

pair<int, int> get_neighborhood(direction_t dir, int y, int x) {
    switch (dir) {
        case RIGHT: x += 1; break;
        case    UP: y -= 1; break;
        case  LEFT: x -= 1; break;
        case  DOWN: y += 1; break;
    }
    return make_pair(y, x);
}

uint16_t pack_t_dir(int t, direction_t dir) {
    return (t << 3) | 4 | (int)dir;
}
pair<int, direction_t> unpack_t_dir(uint16_t packed) {
    return make_pair((int)packed >> 3, (direction_t)(packed & 3));
}

int get_cell_score(int cnt) {
    switch (cnt) {
        case 1: return 10;
        case 2: return  3;
        case 3: return  1;
        default: return 0;
    }
}

struct robots_runner {
    array<array<array<uint16_t, M>, M>, N> used;
    array<array<int16_t, M>, M> cnt;
    array<array<int, M>, M> cost;
    array<array<char, M>, M> f;
    array<pair<int8_t, int8_t>, N> dest;
    const vector<string> s;
    int score;

public:
    robots_runner(vector<string> const & s_)
            : s(s_) {
        used = {};
        cnt = {};
        cost = {};
        score = 0;
        REP (z, M) {
            f[0][z] = '#';
            f[M - 1][z] = '#';
            f[z][0] = '#';
            f[z][M - 1] = '#';
        }
        REP3 (y, 1, M - 1) REP3 (x, 1, M - 1) {
            f[y][x] = '.';
        }
        REP3 (y, 1, M - 1) if (min(y, M - y - 1) >= 2) f[y][M / 2] = 'D';
        REP (i, N) {
            run_robot(i, 0, M / 2, M / 2, UP, true);
        }
    }

    pair<int, int> get_dest(int i, int t, int y, int x, direction_t dir) const {
        for (; t < L; ++ t) {
            char c = s[i][t];
            int k = 1;
            if (f[y][x] == 'D') k = 2;
            if (f[y][x] == 'T') k = 3;
            while (k --) {
                if (c == 'S') {
                    int ny, nx; tie(ny, nx) = get_neighborhood(dir, y, x);
                    if (f[ny][nx] == '#') break;
                    y = ny;
                    x = nx;
                } else if (c == 'L' or c == 'R') {
                    if (f[y][x] == 'L' or f[y][x] == 'R') {
                        c = f[y][x];
                    }
                    if (c == 'R') {
                        dir = rotate_right(dir);
                    } else {
                        dir = rotate_left(dir);
                    }
                } else {
                    assert (false);
                }
            }
        }
        return make_pair(y, x);
    }

    int get_delta(int y, int x, char c) {
        assert (c == '.' or c == 'L' or c == 'R');
        swap(f[y][x], c);
        vector<tuple<int, int, int> > history;

        REP (i, N) if (used[i][y][x]) {
            int y1, x1; tie(y1, x1) = dest[i];
            score -= get_cell_score(cnt[y1][x1]);
            cnt[y1][x1] -= 1;
            score += get_cell_score(cnt[y1][x1]);

            int t; direction_t dir; tie(t, dir) = unpack_t_dir(used[i][y][x]);
            int y2, x2; tie(y2, x2) = get_dest(i, t, y, x, dir);
            score -= get_cell_score(cnt[y2][x2]);
            cnt[y2][x2] += 1;
            score += get_cell_score(cnt[y2][x2]);

            history.emplace_back(i, y2, x2);
        }

        int updated_score = score;
        for (auto const & it : history) {
            int i, y2, x2; tie(i, y2, x2) = it;
            int y1, x1; tie(y1, x1) = dest[i];
            score -= get_cell_score(cnt[y1][x1]);
            cnt[y1][x1] += 1;
            score += get_cell_score(cnt[y1][x1]);
            score -= get_cell_score(cnt[y2][x2]);
            cnt[y2][x2] -= 1;
            score += get_cell_score(cnt[y2][x2]);
        }

        swap(f[y][x], c);
        return updated_score - score;
    }

    void run_robot(int i, int t, int y, int x, direction_t dir, bool is_positive) {
        for (; t < L; ++ t) {
            char c = s[i][t];
            if (c == 'L' or c == 'R') {
                if (is_positive) {
                    if (not used[i][y][x]) {
                        used[i][y][x] = pack_t_dir(t, dir);
                        cost[y][x] += L - t;
                    }
                } else {
                    int t1 = unpack_t_dir(used[i][y][x]).first;
                    if (t <= t1) {
                        used[i][y][x] = 0;
                        cost[y][x] -= L - t1;
                    }
                }
            }
            int k = 1;
            if (f[y][x] == 'D') k = 2;
            if (f[y][x] == 'T') k = 3;
            while (k --) {
                if (c == 'S') {
                    int ny, nx; tie(ny, nx) = get_neighborhood(dir, y, x);
                    if (f[ny][nx] == '#') break;
                    y = ny;
                    x = nx;
                } else if (c == 'L' or c == 'R') {
                    if (f[y][x] == 'L' or f[y][x] == 'R') {
                        c = f[y][x];
                    }
                    if (c == 'R') {
                        dir = rotate_right(dir);
                    } else {
                        dir = rotate_left(dir);
                    }
                } else {
                    assert (false);
                }
            }
        }
        score -= get_cell_score(cnt[y][x]);
        cnt[y][x] += (is_positive ? +1 : -1);
        score += get_cell_score(cnt[y][x]);
        assert (cnt[y][x] >= 0);
        dest[i] = make_pair(y, x);
    }

    void set(int y, int x, char c) {
        assert (c == '.' or c == 'L' or c == 'R');
        array<uint16_t, N> used1 = {};
        REP (i, N) if (used[i][y][x]) {
            used1[i] = used[i][y][x];
            int t; direction_t dir; tie(t, dir) = unpack_t_dir(used1[i]);
            run_robot(i, t, y, x, dir, false);
        }
        f[y][x] = c;
        REP (i, N) if (used1[i]) {
            int t; direction_t dir; tie(t, dir) = unpack_t_dir(used1[i]);
            run_robot(i, t, y, x, dir, true);
        }
    }
};

array<array<char, M>, M> solve(vector<string> const & s) {
    robots_runner runner(s);
    int score = runner.score;
    vector<pair<int8_t, int8_t> > order;
    REP3 (y, 1, M - 1) REP3 (x, 1, M - 1) {
        order.emplace_back(y, x);
    }
    auto cmp_with_cost = [&](pair<int8_t, int8_t> a, pair<int8_t, int8_t> b) {
        return runner.cost[a.first][a.second] < runner.cost[b.first][b.second];
    };
    sort(ALL(order), cmp_with_cost);

    auto result = runner.f;
    int highscore = score;

    xor_shift_128 gen;
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();
    int iteration = 0;
    for (; ; ++ iteration) {
        chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();
        ll elapsed = chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count();
        if (elapsed >= TIME_LIMIT * 0.95) break;
        double temperature = (double)(TIME_LIMIT - elapsed) / TIME_LIMIT;

        static const string table = "..LR";
        int y, x;
        do {
            int i = uniform_int_distribution<int>(0, order.size() * 2 / 3 - 1)(gen);
            tie(y, x) = order[i];
        } while (runner.f[y][x] == '#' or runner.f[y][x] == 'D' or runner.f[y][x] == 'T');
        char c;
        do {
            c = table[uniform_int_distribution<int>(0, table.size() - 1)(gen)];
        } while (c == runner.f[y][x]);

        int delta = runner.get_delta(y, x, c);

        constexpr double BOLTZMANN = 0.2;
        if (delta >= 0 or bernoulli_distribution(exp(BOLTZMANN * delta) * temperature)(gen)) {
            score += delta;
            if (highscore < score) {
                highscore = score;
                result = runner.f;
                cerr << "[*] iteration = " << iteration << ": score = " << score << endl;
            }
            runner.set(y, x, c);
            sort(ALL(order), cmp_with_cost);
        }
    }
    cerr << "[*] total iteration = " << iteration << endl;
    cerr << "[*] highscore = " << highscore << endl;
    return result;
}

int main() {
    int n, m, l; cin >> n >> m >> l;
    assert (n == N);
    assert (m == M);
    assert (l == L);
    vector<string> s(N);
    REP (i, N) cin >> s[i];
    auto f = solve(s);
    REP (y, M) {
        REP (x, M) {
            cout << f[y][x];
        }
        cout << endl;
    }
    return 0;
}
```
