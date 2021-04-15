---
layout: post
redirect_from:
  - /writeup/algo/codeforces/codeforces-576/
  - /blog/2015/09/11/codeforces-576/
date: 2015-09-11T03:40:11+09:00
tags: [ "codeforces", "competitive", "writeup" ]
"target_url": [ "http://codeforces.com/contest/576" ]
---

# Codeforces Round #319 (Div. 1)

<del> こどふぉでも黄色くなりたい </del> 今回ので黄色になった (1715 -> 1900)

<!-- more -->

## [A. Vasya and Petya's Game](http://codeforces.com/contest/576/problem/A) {#a}

通った。でも、提出を焦ってそれで十分なのかあまりよく考えずに投げたのはよくなかった。

1からnの各数の因数で素数の巾になっているものの全体$\\{ p^i \mid 1 \le a \le n,\; p {\rm \; is \; a \; prime},\; i \ge 1,\; p^i | a \\}$。
サンプルに$n = 4,6$があるが、自分で$n = 5,7,8,9$とやってみると検討がつく。

``` c++
#include <iostream>
#include <vector>
#include <map>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
std::vector<int> prime_factors(int n) {
    std::vector<int> result;
    int a = 2;
    while (a*a <= n) {
        if (n % a == 0) {
            result.push_back(a);
            n /= a;
        } else {
            a += 1;
        }
    }
    if (n != 1) result.push_back(n);
    return result;
}
using namespace std;
int main() {
    int n; cin >> n;
    map<int,int> ps;
    repeat_from (i,2,n+1) {
        map<int,int> qs;
        for (int p : prime_factors(i)) qs[p] += 1;
        for (auto q : qs) ps[q.first] = max(ps[q.first], q.second);
    }
    vector<int> result;
    for (auto p : ps) {
        int x = p.first;
        int y = 1;
        repeat (i, p.second) {
            y *= x;
            result.push_back(y);
        }
    }
    cout << result.size() << endl;
    repeat (i, int(result.size())) {
        if (i) cout << ' ';
        cout << result[i];
    }
    cout << endl;
    return 0;
}
```

## [C. Points on Plane](http://codeforces.com/contest/576/problem/C) {#c}

手元のランダムな最大ケースで問題なかったので投げたらpretestでTLEした。参照引き回すようにするとか`cin`を`scanf`にするとかして投げ直した。不安だったが通ってくれた。

解法としては、空間を再帰的に4分割しながらまとめる。線で結んだ場合Cの形にCが並ぶフラクタルっぽい図形になるはず。

``` c++
#include <iostream>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct point_t {
    int x, y;
};
void f(vector<point_t> const & ps, vector<int> & xs, int yl, int yr, int xl, int xr) {
    if (xs.size() < 4) return;
    vector<int> ys[4];
    int ym = (yl + yr) / 2;
    int xm = (xl + xr) / 2;
    for (int x : xs) {
        int i;
        if      (ym <= ps[x].y and xm <= ps[x].x) i = 0;
        else if (ym <= ps[x].y and ps[x].x  < xm) i = 1;
        else if (ps[x].y  < ym and ps[x].x  < xm) i = 2;
        else i = 3;
        ys[i].push_back(x);
    }
    vector<int> zs(xs.size()); zs.clear();
    f(ps, ys[0], ym, yr, xm, xr);
    f(ps, ys[1], ym, yr, xl, xm);
    f(ps, ys[2], yl, ym, xl, xm);
    f(ps, ys[3], yl, ym, xm, xr);
    xs.clear();
    repeat (i,4) {
        copy(ys[i].begin(), ys[i].end(), back_inserter(xs));
    }
}
int main() {
    int n; scanf("%d", &n);
    vector<point_t> ps(n); repeat (i,n) scanf("%d%d", &ps[i].x, &ps[i].y);
    vector<int> xs(n); repeat (i,n) xs[i] = i;
    f(ps, xs, 0, 1000001, 0, 1000001);
    repeat (i,n) {
        if (i) cout << ' ';
        cout << xs[i] + 1;
    }
    cout << endl;
    return 0;
}
```

物理エンジンの実装の衝突判定する部分ってこんなのだったよなあ、と思いながら書いてた。
面積がないので分割線上の処理は今回のにはなかったが。

---

# Codeforces Round #319 (Div. 1)

Bは解けませんでした。終わった直後にちゃんと振り返ってみると怪しい点だらけでたいへん厳しい。
