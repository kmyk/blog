---
layout: post
alias: "/blog/2016/12/17/dwacon2017-prelims-d/"
date: "2016-12-17T22:04:46+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-prelims/tasks/dwango2017qual_d" ]
---

# 第3回 ドワンゴからの挑戦状 予選: D - ネタだけ食べたい寿司

$4.5$完早解きしたので$21$位だった。順位表$1$ページ目からは落ちた。threepipesさんが以前のDDCC参加者内での順位を出してくれており、見ると$9$位なのでその他枠通過の可能性がある。

## solution

$M$回目にネタだけを食べる位置について全て見る。$O(N \log N)$。

寿司$i$で$M$回目のネタだけを食べるとしよう。
寿司$j \lt i$について、$X_j - Y_j$が大きい順に$M-1$個をネタだけで食べ、その他は普通に食べるのがよい。
このような食べ方の際の値は、$i$を$0$から$N-1$まで動かしながらpriority queueで管理すればそれぞれ求まる。

ネタだけを食べる回数が$M$回未満である場合は考慮しなくてよい。列の末尾で自明にネタだけが有利であるため。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
int main() {
    int n, m; cin >> n >> m;
    vector<int> x(n), y(n); repeat (i,n) cin >> x[i] >> y[i];
    vector<int> y_acc; whole(partial_sum, y, back_inserter(y_acc));
    int ans = 0;
    reversed_priority_queue<int> que;
    int acc = 0;
    repeat (i,n) {
        if (que.size() > m-1) {
            acc -= que.top();
            que.pop();
        }
        que.push(x[i] - y[i]);
        acc += x[i] - y[i];
        setmax(ans, y_acc[i] + acc);
    }
    cout << ans << endl;
    return 0;
}
```
