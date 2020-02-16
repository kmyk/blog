---
layout: post
redirect_from:
  - /blog/2015/12/19/srm-676-med/
date: 2015-12-19T02:32:14+09:00
tags: [ "competitive", "writeup", "srm", "nim", "grundy" ]
---

# TopCoder SRM 676 Div1 Medium: BoardEscape

## [Medium: BoardEscape]()

### 解説

トークンは誰でも同じように動かせ、各トークンは独立であるので、impartial gameの和になっている。grundy数を求める。

grundy数を愚直に求めると$O(krc)$となり、明らかに間に合わない。
なんとなく、盤面のgrundy数全体の配列は$k$に関して周期性を持ちそうなので、書いてみると上手くいく。証明はできていない。

### 実装

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
int mex(set<int> const & xs) {
    int y = 0;
    for (int x : xs) {
        if (x == y) {
            ++ y;
        } else {
            break;
        }
    }
    return y;
}

class BoardEscape {
public:
    vector<vector<int> > grundy(vector<string> const & s, int k) {
        int h = s.size();
        int w = s[0].size();
        vector<vector<vector<int> > > history;
        map<vector<vector<int> >,int> lookup;
        vector<vector<int> > g(h, vector<int>(w));
        history.push_back(g);
        lookup[g] = 0;
        repeat_from (i,1,k+1) {
            vector<vector<int> > f = g;
            repeat (y,h) repeat (x,w) {
                if (s[y][x] == 'E') {
                    g[y][x] = 0;
                } else {
                    set<int> gs;
                    repeat (j,4) {
                        int ny = y + dy[j];
                        int nx = x + dx[j];
                        if (0 <= ny and ny < h and 0 <= nx and nx < w) {
                            if (s[ny][nx] != '#') {
                                gs.insert(f[ny][nx]);
                            }
                        }
                    }
                    g[y][x] = mex(gs);
                }
            }
            if (lookup.count(g)) {
                int j = lookup[g];
                int loop = i - j;
                return history[j + (k - i) % loop];
            } else {
                history.push_back(g);
                lookup[g] = i;
            }
        }
        return g;
    }
    string findWinner(vector<string> s, int k) {
        int h = s.size();
        int w = s[0].size();
        vector<vector<int> > gss = grundy(s, k);
        int g = 0;
        repeat (y,h) repeat (x,w) {
            if (s[y][x] == 'T') {
                g ^= gss[y][x];
            }
        }
        return g ? "Alice" : "Bob";
    }
};
```
