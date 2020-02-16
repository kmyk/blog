---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-043-d/
  - /blog/2016/03/28/arc-043-d/
date: 2016-03-28T21:34:35+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy", "beam-search", "chokudai-search", "lie" ]
---

# AtCoder Regular Contest 043 D - 引っ越し

-   <https://beta.atcoder.jp/contests/arc043/tasks/arc043_d>
-   [editorial](http://www.slideshare.net/chokudai/arc043)

嘘解法楽しい

## 解法

chokudai search。

$P_i$以外の全ての$P_j$の位置が決定されているとすると、$P_i$は他の$P_j$の隣に置くことになる。
$P_i$を仮に位置$x$に置いたとする。
既に置かれている$P_j$で、$x$の左のものの総和を$L$とし、右のものの総和を$R$とする。
$P_i$を位置$x$から$x+1$にずらすと結果の値は$L-R$増加し、$x-1$にずらすと$R-L$増加する。
$L = R$でなければ、その方向にずらせるだけずらすことになる。

$P_i$の大きい方から順に決定していくことを考える。
すると上の性質から、左右の端のどちらかに置いていく貪欲が考えられる。
ただしこれは嘘である。例えば以下のような入力でWAる。

```
6 5
6
6
7
7
8
```

しかしこれを提出すると十分たくさんのテストケースでACを貰うことができる。
なので、chokudai searchを実装すると通せる。
beam searchでは足りなかった。

## 実装

初期状態の数が$1$、遷移先の数が高々$2$である。
多様性が欲しいが、単純に使用済みの状態を殺す訳にもいかないので、なんかいい感じに頑張る。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <chrono>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef uint64_t ll;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
struct state_t { ll acc, ofs_l, cnt_l, ofs_r, cnt_r; };
void normalize(state_t & a) {
    if (make_pair(a.ofs_l, a.cnt_l) > make_pair(a.ofs_r, a.cnt_r)) {
        swap(a.ofs_l, a.ofs_r);
        swap(a.cnt_l, a.cnt_r);
    }
}
state_t  left(state_t a, int n, int i, int p) {
    a.acc += (a.ofs_l + a.ofs_r) * p;
    a.acc += a.cnt_r * p * (n-i-1);
    a.ofs_l += a.cnt_l + p;
    a.cnt_l += p;
    normalize(a);
    return a;
}
state_t right(state_t a, int n, int i, int p) {
    a.acc += (a.ofs_l + a.ofs_r) * p;
    a.acc += a.cnt_l * p * (n-i-1);
    a.ofs_r += a.cnt_r + p;
    a.cnt_r += p;
    normalize(a);
    return a;
}
const uint64_t prime = 1000000007;
uint64_t make_hash(state_t const & a) {
    uint64_t e = 0;
    e *= prime; e += a.ofs_l;
    e *= prime; e += a.cnt_l;
    e *= prime; e += a.ofs_r;
    e *= prime; e += a.cnt_r;
    return e;
}
ll beam_search(int n, int m, vector<int> const & ps, int width, unordered_set<uint64_t> & used) {
    vector<state_t> beam; {
        state_t s = {};
        beam.push_back(s);
    }
    vector<state_t> nbeam;
    unordered_set<uint64_t> duplicated;
    repeat (i,m) {
        int p = ps[i];
        nbeam.clear();
        for (state_t & s : beam) {
            nbeam.push_back( left(s, n, i, p));
            nbeam.push_back(right(s, n, i, p));
        }
        sort(nbeam.begin(), nbeam.end(), [](state_t const & a, state_t const & b) { return a.acc > b.acc; });
        beam.clear();
        duplicated.clear();
        for (state_t & s : nbeam) {
            uint64_t key = make_hash(s);
            if (duplicated.count(key)) continue;
            duplicated.insert(key);
            if (nbeam.size() > width) {
                if (used.count(key)) continue;
                used.insert(key);
            }
            beam.push_back(s);
            if (beam.size() >= width) break;;
        }
    }
    return beam.front().acc;
}
int main() {
    int n, m; cin >> n >> m;
    vector<int> ps(m); repeat (i,m) cin >> ps[i];
    sort(ps.rbegin(), ps.rend());
    auto start = chrono::system_clock::now();
    ll ans = 0;
    int width = 100;
    unordered_set<uint64_t> used;
    while (true) {
        setmax(ans, beam_search(n, m, ps, width, used));
        width += 100;
        auto end = chrono::system_clock::now();
        double t = chrono::duration<double>(end - start).count();
        if (t > 1.2) break;
    }
    cout << ans << endl;
    return 0;
}
```
