---
layout: post
alias: "/blog/2016/04/24/jag2016-domestic-c/"
title: "JAG Contest 2016 Domestic C - みさわさんの根付き木"
date: 2016-04-24T22:28:34+09:00
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc", "parse" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016-domestic/tasks/jag2016secretspring_c" ]
---

## solution

単純な構文解析をする。
解析の過程で曖昧性は発生しない。

## implementation

本番に書いたものを少し整形した。

``` c++
#include <iostream>
#include <memory>
#include <cassert>
using namespace std;

struct binary_tree {
    int v;
    shared_ptr<binary_tree> l, r;
};
typedef shared_ptr<binary_tree> binary_tree_ptr;
binary_tree_ptr make_tree(binary_tree_ptr l, int v, binary_tree_ptr r) {
    binary_tree t = { v, l, r };
    return make_shared<binary_tree>(t);
}

void equal(char a, char b) {
    assert (a == b);
}
binary_tree_ptr parse_tree(string const & s, int & i) {
    equal(s[i ++], '(');
    binary_tree_ptr l;
    if (s[i] != ')') l = parse_tree(s, i);
    equal(s[i ++], ')');
    equal(s[i ++], '[');
    int v = 0;
    while (s[i] != ']') {
        v *= 10;
        v += s[i ++] - '0';
    }
    equal(s[i ++], ']');
    equal(s[i ++], '(');
    binary_tree_ptr r;
    if (s[i] != ')') r = parse_tree(s, i);
    equal(s[i ++], ')');
    return make_tree(l, v, r);
}
istream & operator >> (istream & in, binary_tree_ptr & t) {
    int i = 0;
    string s; in >> s;
    t = parse_tree(s, i);
    return in;
}

binary_tree_ptr operator + (binary_tree_ptr const & a, binary_tree_ptr const & b) {
    if (not a or not b) return shared_ptr<binary_tree>();
    return make_tree(a->l + b->l, a->v + b->v, a->r + b->r);
}

ostream & operator << (ostream & out, binary_tree_ptr const & t) {
    if (not t) return out;
    return out << "(" << t->l << ")[" << t->v << "](" << t->r << ")";
}

int main() {
    binary_tree_ptr a, b; cin >> a >> b;
    cout << a + b << endl;
    return 0;
}
```
