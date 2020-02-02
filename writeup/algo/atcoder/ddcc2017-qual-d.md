---
layout: post
alias: "/blog/2017/11/10/ddcc2017-qual-d/"
date: "2017-11-10T23:34:03+09:00"
title: "DISCO presents ディスカバリーチャンネル コードコンテスト2017 予選: D - 石"
tags: [ "competitive", "writeup", "atcoder", "ddcc" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2017-qual/tasks/ddcc2017_qual_d" ]
---

## 感想

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">D問題、「H,Wは偶数です」って言うとショック受ける人がまだいそう</p>&mdash; chokudai(高橋 直大) (@chokudai) <a href="https://twitter.com/chokudai/status/916683083574763520?ref_src=twsrc%5Etfw">October 7, 2017</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


$H, W$は偶数というのに気付かないまま通してしまった。ショック。

## solution

南北方向に対称にしてから東西方向に対称にするのと、その逆をそれぞれ試す。$O(HW)$。
盤面を全部舐めて対応するものを持たなければ削る感じで書くと楽。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

ll solve(int h, int w, int a, int b, vector<string> m) {
    ll result = 0;
    bool modified = false;
    repeat (y, h) {
        repeat (x, w) {
            if (m[y][x] == 'S' and m[y][x] != m[h - y - 1][x]) {
                m[y][x] = '.';
                modified = true;
            }
        }
    }
    if (modified) {
        result += a;
    }
    repeat (y, h) {
        repeat (x, w) {
            if (m[y][x] == 'S' and m[y][x] != m[y][w - x - 1]) {
                m[y][x] = '.';
                m[h - y - 1][x] = '.';
                result += a;
                modified = true;
            }
        }
    }
    if (modified) {
        result += b;
    }
    repeat (y, h) {
        repeat (x, w) {
            if (m[y][x] == 'S') {
                if (2 * y + 1 == h and 2 * x + 1 == w) {
                    m[y][x] = '.';
                    result += a + b;
                } else if (2 * y + 1 == h) {
                    m[y][x] = '.';
                    m[y][w - x - 1] = '.';
                    result += 2 * a + b;
                } else if (2 * x + 1 == w) {
                    m[y][x] = '.';
                    m[h - y - 1][x] = '.';
                    result += a + 2 * b;
                } else {
                    m[y][x] = '.';
                    m[y][w - x - 1] = '.';
                    m[h - y - 1][x] = '.';
                    m[h - y - 1][w - x - 1] = '.';
                    result += max(a, b) + a + b;
                }
            }
        }
    }
    return result;
}

int main() {
    // input
    int h, w, a, b; cin >> h >> w >> a >> b;
    vector<string> m(h); repeat (y, h) cin >> m[y];
    // solve
    ll p = solve(h, w, a, b, m);
    vector<string> t(w, string(h, '\0'));
    repeat (y, h) repeat (x, w) t[x][y] = m[y][x];
    ll q = solve(w, h, b, a, t);
    // output
    printf("%lld\n", max(p, q));
    return 0;
}
```
