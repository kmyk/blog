---
layout: post
redirect_from:
  - /writeup/long/atcoder/rco-contest-2018-qual-b/
  - /blog/2018/02/13/rco-contest-2018-qual-b/
date: "2018-02-13T15:09:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "rco-contest", "marathon-match", "simulated-annealing" ]
"target_url": [ "https://rco-contest-2018-qual.contest.atcoder.jp/tasks/rco_contest_2018_qual_b" ]
---

# 第2回 RCO日本橋ハーフマラソン 予選: B - ゲーム実況者Xのデフラグ

Aと違ってBはだめで$48$位。
総合順位の付け方が「問題Aでの順位$\times$問題Bでの順位」に変更になってなかったら通過が怪しかった。運が良い。

## solution

焼き鈍し ($310000$点)

ランダムに$2$点選んで、swapした場合の点数が$t$以下なら採用。
この$t$を時間と共に下げていく。

焼き鈍しのつもりはまったくなかったが、解説書くために見直すと完全に焼き鈍しだった。
文脈の強い問題を焼き鈍すテクとして覚えておきたい。
でもこれをするぐらいならビームサーチでよさそう。

### 上位者の解法のメモ

$1$位の解法:

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">B：i番目のファイルを移動する場合、i-1番目とi+1番目を頂点とする矩形の中に移動させるのが良い。前記方針で削減できるコストが大きい順に並び替えた後、各ファイルに対し最も大きなコスト削減可能なファイル交換を行う。</p>&mdash; mamekin (@mamemame_fujita) <a href="https://twitter.com/mamemame_fujita/status/962689446154874880?ref_src=twsrc%5Etfw">2018年2月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

chokudaiさんのDP方針 (バグ埋めなければ$1$位だったらしい):

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">A: 適当に強そうなマップを8個選んで、５手先まで読む貪欲をした。５手先に何もない場合は幅優先探索をした。（ここまで組めると１０位）<br>B: 10箇所に分割してDPでスワップするものを決めた。スワップする時に、今回見てる区画以外の良さげなのを見つけたらそれを採用した（ここまで組めると１位）</p>&mdash; chokudai(高橋 直大) (@chokudai) <a href="https://twitter.com/chokudai/status/962693233997365249?ref_src=twsrc%5Etfw">2018年2月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">Bの方針のDPの説明雑過ぎて何も伝わってないと思うんだけど、「K回までskip出来る時の最短経路問題」を解いてる感じです。（間に合わないから区間を10個に等分割してKを振り分けたり、スキップ連続最大数を7にしたりしてる）</p>&mdash; chokudai(高橋 直大) (@chokudai) <a href="https://twitter.com/chokudai/status/962713104248221697?ref_src=twsrc%5Etfw">2018年2月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

この手の「分割して個別にDP」するタイプの解法を思い付けた試しがないが、典型テクとして初手で検討するようにした方がよさそう。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

constexpr int h = 200;
constexpr int w = 200;
constexpr int d = 16000;
constexpr int k = 4000;
bool is_on_field(int y, int x) { return 0 <= y and y < h and 0 <= x and x < w; }

struct point_t {
    int y, x;
};
inline int get_distance(point_t a, point_t b) {
    return abs(b.y - a.y) + abs(b.x - a.x);
}

int calculate_cost(vector<int> const & row, vector<int> const & col, deque<pair<point_t, point_t> > const & swaps) {
    array<array<point_t, w>, h> sector;
    REP (y, h) REP (x, w) sector[y][x] = { y, x };
    REP_R (i, int(swaps.size())) {
        point_t a, b; tie(a, b) = swaps[i];
        swap(sector[a.y][a.x], sector[b.y][b.x]);
    }
    int cost = 0;
    REP (i, d - 1) {
        cost += get_distance(sector[row[i + 1]][col[i + 1]], sector[row[i]][col[i]]);
    }
    return cost;
}

int main() {
    chrono::high_resolution_clock::time_point clock_begin = chrono::high_resolution_clock::now();

    // input
    { string s; getline(cin, s); }
    vector<int> original_row(d), original_col(d);
    REP (i, d) cin >> original_row[i] >> original_col[i];

    // solve
    default_random_engine gen;
    int lowest_cost = INT_MAX;
    deque<pair<point_t, point_t> > result;

    for (int iteration = 0; ; ++ iteration) {
        chrono::high_resolution_clock::time_point clock_end = chrono::high_resolution_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(clock_end - clock_begin).count() >= 3000) break;

        auto row = original_row;
        auto col = original_col;
        deque<pair<point_t, point_t> > swaps;
        array<array<int, w>, h> data;
        REP (y, h) REP (x, w) data[y][x] = -1;
        REP (i, d) {
            data[row[i]][col[i]] = i;
        }

        for (int limit = 1600; limit >= 10; limit -= (limit >= 1000 ? 100 : 5)) {
            REP (iteration, 100000) {
                {
                    int i = uniform_int_distribution<int>(1, d - 2)(gen);
                    int j = i;
                    while (abs(i - j) <= 3 or (i <= 3 and d - 3 < j)) {
                        j = uniform_int_distribution<int>(1, d - 2)(gen);
                    }

                    int delta = 0;
                    delta -= abs(row[i] - row[i - 1]);
                    delta -= abs(col[i] - col[i - 1]);
                    delta -= abs(row[i + 1] - row[i]);
                    delta -= abs(col[i + 1] - col[i]);
                    delta -= abs(row[j] - row[j - 1]);
                    delta -= abs(col[j] - col[j - 1]);
                    delta -= abs(row[j + 1] - row[j]);
                    delta -= abs(col[j + 1] - col[j]);

                    swap(data[row[i]][col[i]], data[row[j]][col[j]]);
                    swap(row[i], row[j]);
                    swap(col[i], col[j]);

                    delta += abs(row[i] - row[i - 1]);
                    delta += abs(col[i] - col[i - 1]);
                    delta += abs(row[i + 1] - row[i]);
                    delta += abs(col[i + 1] - col[i]);
                    delta += abs(row[j] - row[j - 1]);
                    delta += abs(col[j] - col[j - 1]);
                    delta += abs(row[j + 1] - row[j]);
                    delta += abs(col[j + 1] - col[j]);

                    if (delta < - limit) {
                        swaps.emplace_front((point_t) { row[i], col[i] }, (point_t) { row[j], col[j] });
                        if (swaps.size() == k) break;
                    } else {
                        swap(col[i], col[j]);
                        swap(row[i], row[j]);
                        swap(data[row[i]][col[i]], data[row[j]][col[j]]);
                    }
                }
                {
                    int i = uniform_int_distribution<int>(1, d - 2)(gen);
                    int y = row[i];
                    int x = col[i];
                    while (data[y][x] != -1) {
                        y = uniform_int_distribution<int>(0, h - 1)(gen);
                        x = uniform_int_distribution<int>(0, w - 1)(gen);
                    }

                    int delta = 0;
                    delta -= abs(row[i] - row[i - 1]);
                    delta -= abs(col[i] - col[i - 1]);
                    delta -= abs(row[i + 1] - row[i]);
                    delta -= abs(col[i + 1] - col[i]);

                    swap(data[row[i]][col[i]], data[y][x]);
                    swap(row[i], y);
                    swap(col[i], x);

                    delta += abs(row[i] - row[i - 1]);
                    delta += abs(col[i] - col[i - 1]);
                    delta += abs(row[i + 1] - row[i]);
                    delta += abs(col[i + 1] - col[i]);

                    if (delta < - limit) {
                        swaps.emplace_front((point_t) { row[i], col[i] }, (point_t) { y, x });
                        if (swaps.size() == k) break;
                    } else {
                        swap(col[i], x);
                        swap(row[i], y);
                        swap(data[row[i]][col[i]], data[y][x]);
                    }
                }
            }
            if (swaps.size() == k) break;
        }

        int cost = calculate_cost(original_row, original_col, swaps);
        if (cost < lowest_cost) {
            lowest_cost = cost;
            result = swaps;
        }
break;
    }

    // output
    for (auto swp : result) {
        cout << swp.first.y << ' ' << swp.first.x << ' ' << swp.second.y << ' ' << swp.second.x << ' '  << endl;
    }
    return 0;
}
```
