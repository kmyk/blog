---
layout: post
alias: "/blog/2015/09/07/codeforces-329/"
title: "Codeforces Round #192 (Div. 1)"
date: 2015-09-07T23:03:39+09:00
tags: [ "codeforces", "competitive", "writeup" ]
"target_url": [ "http://codeforces.com/contest/329" ]
---

茶会。2完で3位。Aで失敗したのが響いた。

<!-- more -->

## [A. Purification](http://codeforces.com/contest/329/problem/A) {#a}

解くのに1時間以上かかった。操作が十字に効力を発揮する、というのに惑わされたようだ。

他の解いてる人の速度や数を見て、自分の感じている難易度と明かに差があるとは感じていた。
そのようなときはどうするのが正解なのだろうか。

``` c++
#include <iostream>
#include <vector>
#include <deque>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    int n; cin >> n;
    vector<deque<bool> > e(n, deque<bool>(n));
    repeat (y,n) repeat (x,n) { char c; cin >> c; e[y][x] = c == 'E'; }
    vector<pair<int,int> > a, b;
    repeat (y,n) repeat (x,n) {
        if (not e[y][x]) {
            a.emplace_back(y, x);
            break;
        }
    }
    repeat (x,n) repeat (y,n) {
        if (not e[y][x]) {
            b.emplace_back(y, x);
            break;
        }
    }
    if (a.size() == n) {
        for (auto p : a) {
            cout << p.first+1 << ' ' << p.second+1 << endl;
        }
    } else if (b.size() == n) {
        for (auto p : b) {
            cout << p.first+1 << ' ' << p.second+1 << endl;
        }
    } else {
        cout << -1 << endl;
    }
    return 0;
}
```


## [B. Biridian Forest](http://codeforces.com/contest/329/problem/B) {#b}

解けた。

全ての人間の移動速度は同じなので、移動途中に掴まるならばゴールにおいても掴まる、ということに気付けばよい。
するとゴールと主人公の距離よりもゴールから自身への距離のほうが小さいか同じである人間の数を数えればよいと分かる。
盤の面積$S$に対し$O(S \log S)$。

``` c++
#include <iostream>
#include <cctype>
#include <vector>
#include <queue>
template <class T>
using reversed_priority_queue = std::priority_queue<T, std::vector<T>, std::greater<T> >;
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct state_t {
    int cost;
    int x, y;
};
bool operator > (state_t const & a, state_t const & b) {
    return a.cost > b.cost;
}
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
int main() {
    int h, w; cin >> h >> w;
    vector<vector<char> > a(h, vector<char>(w));
    int sy, sx, ey, ex;
    repeat (y,h) repeat (x,w) {
        cin >> a[y][x];
        if (a[y][x] == 'S') { sy = y; sx = x; }
        if (a[y][x] == 'E') { ey = y; ex = x; }
    }
    int l; {
        reversed_priority_queue<state_t> q;
        q.push((state_t){ 0, sx, sy });
        vector<deque<bool> > used(h, deque<bool>(w));
        while (not q.empty()) {
            state_t s = q.top(); q.pop();
            if (used[s.y][s.x]) continue;
            if (s.y == ey and s.x == ex) {
                l = s.cost;
                break;
            }
            used[s.y][s.x] = true;
            repeat (i,4) {
                int ny = s.y + dy[i];
                int nx = s.x + dx[i];
                if (0 <= ny and ny < h and 0 <= nx and nx < w
                        and a[ny][nx] != 'T' and not used[ny][nx]) {
                    q.push((state_t){ s.cost+1, nx, ny });
                }
            }
        }
    }
    int result = 0; {
        reversed_priority_queue<state_t> q;
        q.push((state_t){ 0, ex, ey });
        vector<deque<bool> > used(h, deque<bool>(w));
        while (not q.empty()) {
            state_t s = q.top(); q.pop();
            if (used[s.y][s.x]) continue;
            used[s.y][s.x] = true;
            if (isdigit(a[s.y][s.x])) {
                result += a[s.y][s.x] - '0';
            }
            if (s.cost + 1 <= l) {
                repeat (i,4) {
                    int ny = s.y + dy[i];
                    int nx = s.x + dx[i];
                    if (0 <= ny and ny < h and 0 <= nx and nx < w
                            and a[ny][nx] != 'T' and not used[ny][nx]) {
                        q.push((state_t){ s.cost+1, nx, ny });
                    }
                }
            }
        }
    }
    cout << result << endl;
    return 0;
}
```

2回dijkstra法を走らせてしまったが、1回にまとめるべきだった。


## [C. Graph Reconstruction](http://codeforces.com/contest/329/problem/C) {#c}

解けず。

editorialを見て非決定的な解法を投げたら通った。制約が緩く解の数が多いときは非決定的な方法を考慮すべきか。

試行回数でなく経過時間で打ち切るようにしたが、`... < 2.8`などとしたらTLEした。
`clock()`や`time()`で得られる時間とjudge側の認識する時間に2倍ほどの差があるようだ。

``` c++
#include <iostream>
#include <vector>
#include <set>
#include <algorithm>
#include <cassert>
#include <ctime>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    clock_t start = clock();
    int n, m; cin >> n >> m;
    set<pair<int,int> > e;
    repeat (i,m) {
        int a, b; cin >> a >> b; -- a; -- b;
        if (not (a < b)) swap(a,b);
        e.emplace(a, b);
        e.emplace(b, a);
    }
    vector<int> v(n); repeat (i,n) v[i] = i;
    while ((clock() - start) /(double) CLOCKS_PER_SEC < 1.4) {
        random_shuffle(v.begin(), v.end());
        bool ok = true;
        assert (1 <= m);
        repeat (i,m) {
            if (e.count(make_pair(v[i], v[(i+1)%n]))) {
                ok = false;
                break;
            }
        }
        if (ok) {
            repeat (i,m) {
                cout << v[i]+1 << " " << v[(i+1)%n]+1 << endl;
            }
            return 0;
        }
    }
    cout << -1 << endl;
    return 0;
}
```
