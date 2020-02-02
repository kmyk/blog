---
layout: post
alias: "/blog/2016/10/10/jag2016autumn-c/"
date: "2016-10-10T21:51:34+09:00"
title: "JAG Practice Contest for ACM-ICPC Asia Regional 2016: C - We Don't Wanna Work!"
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc", "implementation" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016autumn/tasks/icpc2016autumn_c" ]
---

今週末にICPC地区予選本番なのでチーム練習をした。
朝14時まで寝てたら、チーム練習しようよと起こしにきてくれた。

## problem

従業員がたくさんいる。
それぞれにはやる気$m_i$と入社時刻$t_i$が定まっていて、その対$(m_i,t_i)$の辞書順で上から$2$割(端数切り捨て)のみが働き、それ以外は一切働かない。
従業員の退社/雇用のqueryが与えられるので、従業員の働く/働かないの変化を出力せよ。

## solution

丁寧に実装。$O((N+M)\log (N+M))$。

働く/働かないが変化するのは働く人たち/働かない人たちの中でrankが最も下/上の人からなので、その順で`priority_queue`を持っておく。
削除queryに関しては、削除済みflagを立てて管理する。

## implementation

実装が重い。
状態の参照のされかたがすごくclassにしたい感じだったので、ここに置くにあたって切り出した。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <map>
#include <queue>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
typedef int incoming_date_t;
struct member_t {
    string name; int motivation; incoming_date_t incoming_date;
};
bool operator < (member_t const & a, member_t const & b) { return make_tuple(a.motivation, a.incoming_date, a.name) < make_tuple(b.motivation, b.incoming_date, b.name); }
bool operator > (member_t const & a, member_t const & b) { return make_tuple(a.motivation, a.incoming_date, a.name) > make_tuple(b.motivation, b.incoming_date, b.name); }
class solver {
    reversed_priority_queue<member_t> workhorse;
    priority_queue<member_t> idle_fellow;
    set<incoming_date_t> removed_workhorse, removed_idle_fellow;
    map<string, incoming_date_t> incoming_date;
    map<string, bool> is_workhorse;
public:
    auto count_workhorse() { return workhorse.size() - removed_workhorse.size(); }
    auto count_idle_fellow() { return idle_fellow.size() - removed_idle_fellow.size(); }
    auto workhorse_limit() {
        int n = count_workhorse() + count_idle_fellow();
        return n * 20 / 100;
    }
    auto clean() {
        while (not workhorse.empty() and removed_workhorse.count(workhorse.top().incoming_date)) {
            member_t a = workhorse.top(); workhorse.pop();
            removed_workhorse.erase(a.incoming_date);
        }
        while (not idle_fellow.empty() and removed_idle_fellow.count(idle_fellow.top().incoming_date)) {
            member_t a = idle_fellow.top(); idle_fellow.pop();
            removed_idle_fellow.erase(a.incoming_date);
        }
    }
    auto update() {
        vector<string> modified;
        clean();
        while (count_workhorse() != workhorse_limit()) {
            member_t a;
            if (count_workhorse() < workhorse_limit()) {
                assert (not idle_fellow.empty());
                a = idle_fellow.top(); idle_fellow.pop();
                workhorse.push(a);
                is_workhorse[a.name] = true;
            } else {
                assert (not workhorse.empty());
                a = workhorse.top(); workhorse.pop();
                idle_fellow.push(a);
                is_workhorse[a.name] = false;
            }
            modified.push_back(a.name);
            clean();
        }
        return modified;
    }
    auto insert(member_t a) {
        is_workhorse[a.name] = not idle_fellow.empty() and idle_fellow.top() < a;
        if (is_workhorse[a.name]) {
            workhorse.push(a);
        } else {
            idle_fellow.push(a);
        }
        incoming_date[a.name] = a.incoming_date;
        vector<string> modified;
        modified.push_back(a.name);
        whole(copy, update(), back_inserter(modified));
        modified.erase(whole(unique, modified), modified.end());
        return modified;
    }
    auto erase(string name) {
        if (is_workhorse[name]) {
            removed_workhorse.insert(incoming_date[name]);
        } else {
            removed_idle_fellow.insert(incoming_date[name]);
        }
        incoming_date.erase(name);
        is_workhorse.erase(name);
        return update();
    }
    auto report(vector<string> const & names) {
        for (auto name : names) {
            cout << name << " is " << (is_workhorse[name] ? "working hard" : "not working") << " now." << endl;
        }
    }
};
int main() {
    solver s;
    int n; cin >> n;
    repeat (i,n) {
        member_t a; cin >> a.name >> a.motivation; a.incoming_date = i;
        s.insert(a);
    }
    int m; cin >> m;
    repeat (j,m) {
        char c; cin >> c;
        if (c == '+') {
            member_t a; cin >> a.name >> a.motivation; a.incoming_date = n+j;
            s.report(s.insert(a));
        } else if (c == '-') {
            string name; cin >> name;
            s.report(s.erase(name));
        }
    }
    return 0;
}
```
