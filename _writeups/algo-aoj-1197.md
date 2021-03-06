---
layout: post
redirect_from:
  - /writeup/algo/aoj/1197/
  - /blog/2017/06/28/aoj-1197/
date: "2017-06-28T12:41:20+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1197" ]
---

# AOJ 1197 : サイコロ職人 / A Die Maker

サイコロライブラリはなかったので書いた。
正六面体群じゃん$\mathfrak{S}\_4$と同型でしょというのは分かったが、特にその事実は利用できなかった。
視点を固定し$2$面を保持すれば全て求まるが、これが操作が楽でよさそう。

## solution

厳密に打ち切りをすれば一直線に探索できる。
$O(\sum t\_i)$ただし定数として$6! = 720$が乗る。

最終的な面に書かれた数字の配置は自由である。$6!$通りあるので固定し、それぞれについて考える。
目標となる配置が固定されれば、それをちょうど$0$にすることを考えればよい。
サイコロを操作列が小さい方から深さ優先的に見付かるまで転がしていくとする。
このとき手詰まりでないことが$O(1)$で判定できれば探索は後戻りが発生せず、全体で転がす回数の線形で$O(\sum t\_i)$となる。

手詰まりかどうかの(ほとんど必要条件もであるような)十分条件を考える。
サイコロの面を$A\_1, A\_2, B\_1, B\_2, C\_1, C\_2$とし同じアルファベットの面は対面にあるとして、$N\_A$を$A\_1, A\_2$が下に来ないといけない回数の和、$N\_B, N\_C$も同様にする。
このとき、以下を全て満たすことがそれ。

-   $N\_A + N\_B \le N\_C$
-   $N\_B + N\_C \le N\_A$
-   $N\_C + N\_A \le N\_B$

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <functional>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

struct dice_t { // regular hexahedron group
    //       ______
    //      \      \      4
    //     / \   C  \    2156
    //    / A \______\    3 ^
    //    \ A /    B /   ^^ |
    //     \ /   B  /    ab bottom
    //      v__B___/
    int a, b; // in [1, 6]
    int c() const {
        static const int table[6][6] = {
            { 0, 3, 5, 2, 4, 0 },
            { 4, 0, 1, 6, 0, 3 },
            { 2, 6, 0, 0, 1, 5 },
            { 5, 1, 0, 0, 6, 2 },
            { 3, 0, 6, 1, 0, 4 },
            { 0, 4, 2, 5, 3, 0 },
        };
        assert (table[a-1][b-1] != 0);
        return  table[a-1][b-1];
    }
};
dice_t rotate_up(   dice_t dice) { return (dice_t) { dice.a, 7 - dice.c() }; }
dice_t rotate_right(dice_t dice) { return (dice_t) { 7 - dice.c(), dice.b }; }
dice_t rotate_down( dice_t dice) { return (dice_t) { dice.a, dice.c() }; }
dice_t rotate_left( dice_t dice) { return (dice_t) { dice.c(), dice.b }; }

int main() {
    while (true) {
        // input
        array<int, 6> target; repeat (i, 6) scanf("%d", &target[i]);
        if (whole(count, target, 0) == 6) break;
        int p, q; scanf("%d%d", &p, &q); -- p; // [l, r)
        // solve
        string result = "impossible";
        do {
            array<int, 6> t = target;
            auto is_impossible = [&]() {
                int a = t[2 - 1] + t[5 - 1];
                int b = t[3 - 1] + t[4 - 1];
                int c = t[1 - 1] + t[6 - 1];
                if (a + b < c - 1) return true;
                if (b + c < a - 1) return true;
                if (c + a < b - 1) return true;
                return false;
            };
            string acc;
            function<bool (char, dice_t)> dfs = [&](char c, dice_t dice) {
                if (t[7 - dice.c() - 1] == 0) return false;
                t[7 - dice.c() - 1] -= 1;
                if (whole(count, t, 0) == 6) { acc += c; return true; }
                if (not is_impossible()) {
                    if (dfs('E', rotate_right(dice))) { acc += c; return true; }
                    if (dfs('N', rotate_up   (dice))) { acc += c; return true; }
                    if (dfs('S', rotate_down (dice))) { acc += c; return true; }
                    if (dfs('W', rotate_left (dice))) { acc += c; return true; }
                }
                t[7 - dice.c() - 1] += 1;
                return false;
            };
            t[6 - 1] += 1;
            dfs('$', (dice_t) { 2, 3 });
            if (acc != "") {
                acc.pop_back();
                whole(reverse, acc);
                setmin(result, acc);
            }
        } while (whole(next_permutation, target));
        if (result != "impossible") {
            result = result.substr(p, q - p);
        }
        printf("%s\n", result.c_str());
    }
    return 0;
}
```
