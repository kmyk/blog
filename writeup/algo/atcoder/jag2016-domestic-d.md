---
layout: post
alias: "/blog/2016/04/24/jag2016-domestic-d/"
date: 2016-04-24T22:28:37+09:00
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016-domestic/tasks/jag2016secretspring_d" ]
---

# JAG Contest 2016 Domestic D - インビジブル

本番はペアプロした。私が見る側。実装が汚い(本番だったので仕方がない)のが原因でバグに苦しめられた。
本番中は実装が重い気がしていたが、後から清書した結果そうでもない気がしてきた。

ところで`int memo[2][51][51][51][51][3];`みたいなのの初期化を`rep (p,2) rep (i,50) rep (j,50) rep (k,50) rep (l,50) rep (q,3) { ... }`とするとWAる。気付きにくい。

## solution

メモ化全探索。$O(N^2M^2)$。

手番の別$t = 2$とパスの回数$p = 3$、プレイヤーの使ったカードの枚数$n, m$と、実質的に場に出ているカードの枚数$n, m$とし、状態数は高々$tpn^2m^2$。
これは間に合う。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
struct state_t {
    vector<int> const & deck;
    int used;
    int stack;
};
bool operator < (state_t const & s, state_t const & t) {
    return make_tuple(&s.deck, s.used, s.stack) < make_tuple(&t.deck, t.used, t.stack);
}
int score(state_t const & s) {
    int acc = 0;
    repeat (i, s.stack) {
        int card = s.deck[s.used-1 - i];
        if (card != -1) acc += card;
    }
    return acc;
}
const int inf = 1e9+7;
typedef tuple<state_t, state_t, int> key_type;
int dfs(state_t const & s, state_t const & t, int pass_count, map<key_type,int> & memo) {
    auto key = make_tuple(s, t, pass_count);
    if (memo.count(key)) return memo[key];
    int use_score = - inf;
    if (s.used < s.deck.size()) {
        state_t ns = { s.deck, s.used + 1, s.stack + 1 };
        state_t nt = { t.deck, t.used, s.deck[s.used] == -1 ? 0 : t.stack };
        use_score = - dfs(nt, ns, 0, memo);
    }
    int pass_score;
    if (pass_count + 1 == 3) {
        pass_score = 0;
    } else {
        state_t ns = { s.deck, s.used, 0 };
        state_t nt = { t.deck, t.used, 0 };
        pass_score = score(s) - score(t) - dfs(nt, ns, pass_count + 1, memo);
    }
    return memo[key] = max(use_score, pass_score);
}
int main() {
    int n, m; cin >> n >> m;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> b(m); repeat (i,m) cin >> b[i];
    state_t s = { a, 0, 0 };
    state_t t = { b, 0, 0 };
    map<key_type,int> memo;
    int ans = dfs(s, t, 1, memo);
    cout << ans << endl;
    return 0;
}
```
