---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/433/
  - /blog/2016/10/15/yuki-433/
date: "2016-10-15T00:43:27+09:00"
tags: [ "competitive", "writeup", "yukicoder", "implementation" ]
"target_url": [ "http://yukicoder.me/problems/no/433" ]
---

# Yukicoder No.433 ICPC国内予選の選抜ルールがこんな感じだったらうれしい

指示通りやるだけ。
放送では実装が重いように言っていたが、軽いと思う。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
struct team_t {
    int solved, penalty, university;
    int index, rank_in_university;
};
bool operator < (team_t const & a, team_t const & b) {
    return make_tuple(- a.solved, a.rank_in_university, a.penalty, a.index, a.university)
        <  make_tuple(- b.solved, b.rank_in_university, b.penalty, a.index, b.university); // reversed
}
int main() {
    int n, k; cin >> n >> k;
    vector<team_t> team(n);
    repeat (i,n) {
        cin >> team[i].solved >> team[i].penalty >> team[i].university;
        team[i].index = i;
    }
    map<int,vector<int> > univ;
    repeat (i,n) univ[team[i].university].push_back(i);
    for (auto & it : univ) {
        vector<int> & ix = it.second;
        whole(sort, ix, [&](int i, int j) { return team[i] < team[j]; });
        repeat (j, ix.size()) team[ix[j]].rank_in_university = j;
    }
    whole(sort, team);
    repeat (i,k) cout << team[i].index << endl;
    return 0;
}
```
