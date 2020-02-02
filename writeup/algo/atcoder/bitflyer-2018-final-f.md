---
layout: post
title: "codeFlyer （bitFlyer Programming Contest）: F - 配信パズル"
date: 2018-07-02T20:13:44+09:00
tags: [ "competitive", "writeup", "atcoder", "codeflyer", "data-structure" ]
"target_url": [ "https://beta.atcoder.jp/contests/bitflyer2018-final-open/tasks/bitflyer2018_final_f" ]
---

## solution

$1$回解くだけならライツアウトの自明版。
黒マスを含む列/行の集合を管理する感じの延長を頑張る。
$O((HW + Q (H + W))(\log H + \log W))$。

とりあえず$Q = 1$の場合を考える。
操作は線形で可換なので「行反転/列反転を上手くやって高々ひとつまでの長方形だけにできるか」という問題だと言える。
最上行と最左列はとりあえずすべて白にしてよい(ありがち)ことが言えるので、よって$O(HW)$で(もし存在するなら)正解の形にできる。
それが正解であるかの判定は、各行/各列の黒マスの数を管理するとかでいい感じ(典型)にしておけば更新が$O(\log H + \log W)$で判定が$O(1)$になる。

次に$Q \ge 2$の場合。
「最上行と最左列がすべて白」という状態を保てばよい。
操作は可換であったので状態をほぼ使い回せる。
しかし上左隅$(1, 1)$に反転が来た場合だけは愚直には$O(HW (\log H + \log W))$で困る。
しかしよく見るとこれは「最上行でも最左列でもないマスすべての反転」と等価なのでいい感じ(典型)にできる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

class solver {
    int h, w;
    vector<string> s;
    bool is_reversed;
    map<int, int> row[2];
    map<int, int> col[2];
    int cnt[2];

public:
    solver(int h, int w, vector<string> const & s0)
            : h(h), w(w) {
        // initialize data
        s.resize(h - 1, string(w - 1, '\0'));
        is_reversed = false;
        cnt[0] = cnt[1] = 0;
        REP (y, h - 1) REP (x, w - 1) {
            char & p = s[y][x];
            p = (s0[y][x] == '#');
            ++ row[p][y];
            ++ col[p][x];
            ++ cnt[p];
        }

        // eliminate bottom-row and rightmost-column
        REP (x, w - 1) if (s0[h - 1][x] == '#') {
            flip_col(x);
        }
        REP (y, h - 1) if (s0[y][w - 1] == '#') {
            flip_row(y);
        }
        if (s0[h - 1][w - 1] == '#') {
            flip_board();
        }
    }

    void update(int y, int x) {
        if (y == h - 1 and x == w - 1) {
            flip_board();
        } else if (y == h - 1) {
            flip_col(x);
        } else if (x == w - 1) {
            flip_row(y);
        } else {
            flip_point(y, x);
        }
    }

    bool answer() const {
        bool p = not is_reversed;
        if (cnt[p] == 0) return true;
        int size_h = row[p].rbegin()->first - row[p].begin()->first + 1;
        int size_w = col[p].rbegin()->first - col[p].begin()->first + 1;
        return size_h * size_w == cnt[p];
    }

private:
    void flip_point(int y, int x) {
        char & p = s[y][x];
        if (-- row[p][y] == 0) row[p].erase(y);
        if (-- col[p][x] == 0) col[p].erase(x);
        -- cnt[p];
        p ^= 1;
        ++ row[p][y];
        ++ col[p][x];
        ++ cnt[p];
    }
    void flip_row(int y) {
        REP (x, w - 1) flip_point(y, x);
    }
    void flip_col(int x) {
        REP (y, h - 1) flip_point(y, x);
    }
    void flip_board() {
        is_reversed ^= 1;
    }
};

int main() {
    int h, w, q; cin >> h >> w >> q;
    vector<string> s(h);
    REP (y, h) cin >> s[y];
    solver slvr(h, w, s);
    REP (i, q) {
        if (i >= 1) {
            int y, x; cin >> y >> x;
            -- y;
            -- x;
            slvr.update(y, x);
        }
        bool ans = slvr.answer();
        cout << (ans ? "Yes" : "No") << endl;
    }

    return 0;
}
```
