---
redirect_from:
layout: post
date: 2018-11-22T22:08:44+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2018-final/tasks/code_festival_2018_final_d" ]
---

# CODE FESTIVAL 2018 Final: D - Three Letters

## 解法

### 概要

DPで各文字列ごとに作成可能な略称をすべて列挙すればよい。
テストケースは強いが制約が小さいので通ってしまう。
文字種 $$L = 52$$ に対し $$O(N L^3 + (\sum |A_i|) L^2)$$ となる。

## メモ

想定は中央を固定。
A問題と同様な感じでやる。
賢いけどよく考えると計算量は落ちてないように思う。
$$L = 52 \le 64$$ なので$$1$$命令でできるという意味では落ちてるが、もしそうだとすると「想定が定数倍高速化」になってしまう気がする。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

constexpr int L = 52;
int encode(char c) {
    assert (('A' <= c and c <= 'Z') or ('a' <= c and c <= 'z'));
    return ('a' <= c ? c - 'a' + 26 : c - 'A');
}
char decode(int i) {
    assert (0 <= i and i < L);
    return (i < 26 ? 'A' + i : 'a' + i - 26);
}

string solve(int n, vector<string> const & a) {
    // count abbrs
    int cnt[L][L][L] = {};
    for (string const & s : a) {
        bool used[L][L + 1][L + 1] = {};
        for (char c : s) {
            REP (i, L) if (used[i][L][L]) {
                REP (j, L) if (used[i][j][L]) {
                    if (not used[i][j][encode(c)]) {
                        used[i][j][encode(c)] = true;
                        cnt[i][j][encode(c)] += 1;
                    }
                }
                used[i][encode(c)][L] = true;
            }
            used[encode(c)][L][L] = true;
        }
    }

    // make the string
    string s = "...";
    int used = -1;
    REP (i, L) {
        REP (j, L) {
            REP (k, L) {
                if (used < cnt[i][j][k]) {
                    used = cnt[i][j][k];
                    s[0] = decode(i);
                    s[1] = decode(j);
                    s[2] = decode(k);
                }
            }
        }
    }
    return s;
}

int main() {
    int n; cin >> n;
    vector<string> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, a) << endl;
    return 0;
}
```
