---
layout: post
alias: "/blog/2015/10/24/kupc-2015-f/"
title: "京都大学プログラミングコンテスト2015 F - 逆ポーランド記法"
date: 2015-10-24T23:55:42+09:00
tags: [ "kupc", "competitive", "writeup", "reverse-polish-notation", "queue", "stack", "dfs", "bfs" ]
---

| stack | queue |
|  dfs  |  bfs  |

という対応は綺麗なので好き。

結構時間取られた。1時間半ぐらい。

<!-- more -->

## [F - 逆ポーランド記法](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_f) {#f}

### 問題

逆ポーランド記法の式が与えられる。
逆ポーランド記法の式の計算の際にstackでなくqueueを使って計算した場合に、元の計算結果と同じ結果になるようにこの式を並び換えよ。

### 解法

類推と実験か。

```
       -
   *       +
 +   *   -   -
1 2 3 4 5 6 7 8
```

という木で表される式があるとする。

このとき、stackの(つまり普通の)rpnであれば、

```
       15
   7       14
 3   6   10  13
1 2 4 5 8 9 11 12
```

という順で書き、`12+34**56-78-+-`となる。これはdfs。

一方、queueのrpnであれば、

```
       15
   14      13
 12  11  10  9
8 7 6 5 4 3 2 1
```

という順で書き、`87654321--*++*-`となる。これはbfs。

### 実装

競技で`new`したの始めてかも。

``` c++
#include <iostream>
#include <vector>
#include <stack>
#include <map>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct expr_t {
    char c;
    expr_t *l;
    expr_t *r;
};
expr_t *alloc_expr(char c, expr_t *l, expr_t *r) {
    expr_t *e = new expr_t;
    e->c = c;
    e->l = l;
    e->r = r;
    return e;
}
expr_t *parse(string const & s) {
    stack<expr_t *> x;
    for (char c : s) {
        if (isdigit(c)) {
            x.push(alloc_expr(c, NULL, NULL));
        } else {
            assert (c == '+' or c == '-' or c == '*');
            assert (x.size() >= 2);
            expr_t *r = x.top(); x.pop();
            expr_t *l = x.top(); x.pop();
            x.push(alloc_expr(c, l, r));
        }
    }
    assert (x.size() == 1);
    return x.top();
}
void format(expr_t *e, int i, map<int,string> & acc) {
    if (e == NULL) return;
    acc[i] += e->c;
    format(e->r, i+1, acc);
    format(e->l, i+1, acc);
}
string format(expr_t *e) {
    map<int,string> acc;
    format(e, 0, acc);
    string s;
    for (auto p : acc) s = p.second + s;
    return s;
}
int main() {
    string s; cin >> s;
    expr_t *e = parse(s);
    cout << format(e) << endl;
    return 0;
}
```

#### 実験用 stack

``` c++
#include <iostream>
#include <stack>
#include <cassert>
using namespace std;
int main() {
    string s; cin >> s;
    stack<int> x;
    for (char c : s) {
        if (isdigit(c)) {
            x.push(c - '0');
        } else {
            assert (c == '+' or c == '-' or c == '*');
            assert (x.size() >= 2);
            int r = x.top(); x.pop();
            int l = x.top(); x.pop();
            x.push(c == '+' ? l + r :
                    c == '-' ? l - r :
                    l * r);
        }
    }
    assert (x.size() == 1);
    cout << x.top() << endl;
    return 0;
}
```

#### 実験用 queue

``` c++
#include <iostream>
#include <queue>
#include <cassert>
using namespace std;
int main() {
    string s; cin >> s;
    queue<int> x;
    for (char c : s) {
        if (isdigit(c)) {
            x.push(c - '0');
        } else {
            assert (c == '+' or c == '-' or c == '*');
            assert (x.size() >= 2);
            int r = x.front(); x.pop();
            int l = x.front(); x.pop();
            x.push(c == '+' ? l + r :
                    c == '-' ? l - r :
                    l * r);
        }
    }
    assert (x.size() == 1);
    cout << x.front() << endl;
    return 0;
}
```
