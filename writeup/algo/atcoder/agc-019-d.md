---
layout: post
alias: "/blog/2017/08/27/agc-019-d/"
date: "2017-08-27T00:14:33+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "binary-search", "lie" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc019/tasks/agc019_d" ]
---

# AtCoder Grand Contest 019: D - Shift and Flip

ストレステストと嘘とテストケースの弱さを使ってAC。
つまりバグが残っている。
鯖側のテストだと$1000$ケースとかは用意してはいられないのでまあはい。

## solution

最終状態の$A$の先頭が元々のAの何番目だったのかを総当たり。
$A\_l$が先頭に移動するとして、それに加えて$0,1$の反転のために右に$d\_r$移動して戻る/左に$d\_l$移動して戻るという操作が必要。
この$l, d\_l, d\_r$について総当たりを愚直で書けば$O(N^4)$。
そこから$l$だけ決めて残りを二分探索とかでいい感じにするようにしたら$O(N^2 \log N)$。

まず$l$を固定する。
$A\_l$を先頭にするのには左shiftを$l$回使うとしてよい。
$A\_i$を$i$から$i - l$に動かす過程で$B$に$1$がなくかつ動かした後で不一致のときを考える。
そのような$i$のそれぞれについて、左に$l$動かす前に右にいくつ動かせば$1$に辿り着くかを$d\_r(i)$、左へ$l$動かした後に左にいくつ動かせばを同様に$d\_l(i)$とする。これは二分探索で決定できる。
$(d\_l, d\_r)$は$\forall i. d\_l(i) \le d\_l \lor d\_r(i) \le d\_r$を満たせばよく、これはsortしていい感じにすれば$O(N \log N)$で求まる。

## implementation

嘘実装。$\mathrm{popcnt}(A) = N$で分岐してある場合を除いて$\mathrm{popcnt}(B) = 1$なケースで落ちる。

``` c++
#include <algorithm>
#include <cassert>
#include <iostream>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x in [l, r) | p(x) }, or r
}

constexpr int inf = 1e9+7;
int solve(string const & a, string const & b) {
    if (not count(whole(b), '1')) {
        return count(whole(a), '1') ? -1 : 0;
    }
    int n = a.size();
    if (count(whole(a), '1') == n and count(whole(b), '1') == 1) {
        return 2 * n - 2; // ???
    }
    vector<int> b_acc(n + 1);
    repeat (i, n) b_acc[i + 1] = b_acc[i] + (b[i] == '1');
    auto get_b_acc = [&](int l, int r) { return b_acc[r] - b_acc[l] + (l > r ? b_acc[n] : 0); };
    int result = inf;
    repeat (l, n) {
        vector<pair<int, int> > que;
        int cnt = 0;
        repeat (j, n) {
            int i = (l + j) % n;
            if (a[i] != b[j]) {
                cnt += 1;
                if (not get_b_acc(j, i + 1)) {
                    int dl = binsearch(0, n, [&](int d) {
                        return get_b_acc((j - d + n) % n, j);
                    });
                    int dr = binsearch(0, n, [&](int d) {
                        return get_b_acc(i + 1, (i + 1 + d) % n);
                    });
                    que.emplace_back(dl, dr);
                }
            }
        }
        int delta = n;
        if (que.empty()) {
            delta = 0;
        } else {
            sort(whole(que));
            int acc = 0;
            repeat_reverse (i, que.size()) {
                setmin(delta, 2 * que[i].first + 2 * acc);
                acc = max(acc, que[i].second);
            }
            setmin(delta, 2 * acc);
        }
        setmin(result, l + cnt + delta);
    }
    return result;
}

int main() {
    string a, b; cin >> a >> b;
    int result = inf;
    setmin(result, solve(a, b));
    reverse(whole(a));
    reverse(whole(b));
    setmin(result, solve(a, b));
    cout << result << endl;
    return 0;
}
```
