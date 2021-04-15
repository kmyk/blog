---
redirect_from:
  - /writeup/algo/codeforces/1023-e/
layout: post
date: 2018-08-18T02:14:39+09:00
tags: [ "competitive", "writeup", "codeforces", "reactive", "maze" ]
"target_url": [ "http://codeforces.com/contest/1023/problem/E" ]
---

# Codeforces Round #504 (rated, Div. 1 + Div. 2, based on VK Cup 2018 Final): E. Down or Right

## solution

可能な道の中で最も上側のものを探す。
$(1, 2) - (n, n)$ を聞いて `YES` なら $(1, 2)$ に進み `NO` なら $(2, 1)$ に進む。
$(1, 2)$ にいるとき $(1, 3) - (n, n)$ を聞いて `YES` なら $(1, 3)$ に進み `NO` なら $(2, 2)$ に進む。
そのように続けていき、対角線まで来たらゴールから逆向きに同様なことをする。
合計$2n - 3$クエリ。

## note

下手に手元でテスト書いて検証するより、$-50$点いくつか貰ってでもさっさと捩じ込んだ方が点数高くなる気がしてきた

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;

bool query(int y1, int x1, int y2, int x2) {
    cout << "? " << y1 + 1 << " " << x1 + 1 << " " << y2 + 1 << " " << x2 + 1 << endl;
    cout.flush();
    string s; cin >> s;
    assert (s == "YES" or s == "NO");
    return s == "YES";
}

int main() {
    int n; cin >> n;
    vector<string> f(n, string(n, '?'));
    f[0][0] = f[n - 1][n - 1] = '.';

    // explore the upper half of the maze
    for (int y = 0, x = 0; y + x < n - 1; ) {
        if (query(y, x + 1, n - 1, n - 1)) {
            ++ x;
        } else {
            ++ y;
        }
        f[y][x] = '.';
    }

    // explore the lower half of the maze
    for (int y = n - 1, x = n - 1; y + x > n; ) {
        if (query(0, 0, y - 1, x)) {
            -- y;
        } else {
            -- x;
        }
        f[y][x] = '.';
    }

    // construct a path
    string s;
    for (int y = 0, x = 0; y != n - 1 or x != n - 1; ) {
        if (y + 1 < n and f[y + 1][x] == '.') {
            s += 'D';
            ++ y;
        } else if (x + 1 < n and f[y][x + 1] == '.') {
            s += 'R';
            ++ x;
        } else {
            assert (false);
        }
    }
    cout << "! " << s << endl;
    cout.flush();
    return 0;
}
```

``` python
#!/usr/bin/env python3
import random
import sys

def is_reachable(n, f, y1, x1, y2, x2):
    if f[y1][x1] or f[y2][x2]:
        return False
    used = [ [ False for x in range(n) ] for y in range(n) ]
    stk = [ (y1, x1) ]
    used[y1][x1] = True
    while stk:
        y, x = stk.pop()
        for ny, nx in [ (y + 1, x), (y, x + 1) ]:
            if ny <= y2 and nx <= x2 and not f[ny][nx] and not used[ny][nx]:
                stk.append((ny, nx))
                used[ny][nx] = True
    return used[y2][x2]

def walk_maze(n, f, s):
    y, x = 0, 0
    for c in s:
        if c == 'D':
            y += 1
        elif c == 'R':
            x += 1
        assert y < n and x < n
        assert not f[y][x]
    return True

def main():
    # n = random.randint(2, 500)
    n = random.randint(2, 50)
    print(n)
    sys.stdout.flush()
    print('[*] n =', n, file=sys.stderr)

    print('[*] finding...', file=sys.stderr)
    while True:
        f = [ [ random.random() < max(0.2, 0.4 - n / 800) for x in range(n) ] for y in range(n) ]
        if is_reachable(n, f, 0, 0, n - 1, n - 1):
            break
    print('[*] found', file=sys.stderr)
    for y in range(n):
        print(''.join([ '.#'[f[y][x]] for x in range(n) ]), file=sys.stderr)

    for i in range(4 * n + 1):
        type, *args = input().split()
        print('[*] query', i, ':', type, *args, file=sys.stderr)

        if type == '?':
            y1, x1, y2, x2 = map(lambda arg: int(arg) - 1, args)
            assert y1 <= y2
            assert x1 <= x2
            assert (y2 - y1) + (x2 - x1) >= n - 1
            print(['NO', 'YES'][is_reachable(n, f, y1, x1, y2, x2)])

        elif type == '!':
            s, = args
            assert len(s) == 2 * n - 2
            assert walk_maze(n, f, s)
            return True

        else:
            assert False
    return False

assert main()
```
