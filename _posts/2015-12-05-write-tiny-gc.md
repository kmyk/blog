---
category: blog
layout: post
redirect_from:
    - "/blog/2015/12/04/write-tiny-gc/"
date: 2015-12-05T02:36:10+09:00
tags: [ "lazyk", "gc", "interpreter" ]
---

# 簡単なGCを書いてみたらメモリ使用量が1/1000になって驚いた話

言語処理系を書きたくなって、とりあえずはlazykを実装し、gcも書いてみたかったので書きました。
するとふわっと書いた80行ほどのgcなのに、あるケースでのメモリ消費量を5GBから3MBへ、実に1/1000になりました。
すごい。楽しい。

garbage collectionといっても、dfsして到達できないものの使用中フラグを倒すだけなので実際やるだけ。
世代別だとかincrementalだとかに手をだすと楽しくなりそう。
次はcでlisp処理系を書きたいなと思っている。

<!-- more -->

## 計測

[lazyk製のunlambda interpreter](http://esoteric.sange.fi/essie2/download/lazy-k/eg/unlambda.lazy)の上で[unlambdaのquine](ftp://ftp.madore.org/pub/madore/unlambda/CUAN/quine/quine00.unl)を動かして計測した。
他の場合は特に調べていない雑な計測であることに注意。

gc入れると速度も改善してるのは面白い。

### gc無し

5.2GB

``` sh
$ g++ -std=c++11 -O2 -DNOGC a.cpp && diff <(\time -f '%MKB (%esec)' ./a.out unlambda.lazy < quine00.unl) quine00.unl
5294160KB (10.07sec)
```

### gc有り

3.7MB

``` sh
$ g++ -std=c++11 -O2 a.cpp && diff <(\time -f '%MKB (%esec)' ./a.out unlambda.lazy < quine00.unl) quine00.unl
3764KB (6.20sec)
```

## 実装

実装は載せておくが、gcの素人が書いたものなので、これを参考にするのはおすすめしない。
あくまでこの記事は、gc書くの面白いよ、意外と簡単だったよ、ということを言いたい記事である。

### 概略

確保した領域の列と、今だいたいとこまで使ったかを指す変数、開放してはいけない対象の列を、とりあえずglobal変数として確保。

``` c++
vector<pair<term_t *,size_t> > pools;
int pool_y = 0;
int pool_x = 0;
vector<term_t *> roots;
```

構造体内に印を付ける場所を埋め込む。

``` c++
enum tag_t { Free = '\0', Ap = '`', S = 's', K = 'k', I = 'i', Succ = '+', Num = 'n', In = ',' };
struct term_t {
    tag_t tag;
    term_t *x, *y;
#ifndef NOGC
    bool mark;
#endif
};
```

到達できる対象に印を付けてまわる関数。dfsするだけ。

``` c++
void mark_recursively(term_t *t) {
    ...
    if (t->x) mark_recursively(t->x);
    if (t->y) mark_recursively(t->y);
}
```

gcとは、rootから到達可能な対象に印を付けてみて、付いてないやつを削除する。

``` c++
void garbage_collect() {
    ...
        mark_recursively(root);
    ...
            if (not pools[y].first[x].mark) {
                pools[y].first[x] = { Free };
            }
    ...
}
```

次の使用可能な領域を探す関数。これは単に線形探索する。

``` c++
void find_space() {
    while (pool_y < pools.size()) {
        while (pool_x < pools[pool_y].second) {
            ...
        }
        ...
    }
}
```

`new`や`malloc`の代わりに使う関数を作り、これを使う。探してなければgcをする。

``` c++
term_t *allocate() {
    find_space();
    ...
        garbage_collect();
    ...
}
```

### 完全な実装

``` c++
#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
using namespace std;

enum tag_t { Free = '\0', Ap = '`', S = 's', K = 'k', I = 'i', Succ = '+', Num = 'n', In = ',' };
struct term_t {
    tag_t tag;
    term_t *x, *y;
#ifndef NOGC
    bool mark;
#endif
};

#ifndef NOGC
vector<pair<term_t *,size_t> > pools;
int pool_y = 0;
int pool_x = 0;
vector<term_t *> roots;
void mark_recursively(term_t *t) {
    if (t->mark) return;
    t->mark = true;
    if (t->tag == Num) return;
    if (t->x) mark_recursively(t->x);
    if (t->y) mark_recursively(t->y);
}
void garbage_collect() {
    for (auto & it : pools) {
        term_t *pool = it.first;
        for (int i = 0; i < it.second; ++ i) {
            pool[i].mark = false;
        }
    }
    for (term_t *root : roots) {
        mark_recursively(root);
    }
    pool_y = pools.size();
    pool_x = 0;
    bool is_space_found = false;
    for (int y = 0; y < pools.size(); ++ y) {
        for (int x = 0; x < pools[y].second; ++ x) {
            if (not pools[y].first[x].mark) {
                pools[y].first[x] = { Free };
            }
            if (not is_space_found and pools[y].first[x].tag == Free) {
                is_space_found = true;
                pool_y = y;
                pool_x = x;
            }
        }
    }
}
void find_space() {
    while (pool_y < pools.size()) {
        while (pool_x < pools[pool_y].second) {
            if (pools[pool_y].first[pool_x].tag == Free) {
                return;
            }
            ++ pool_x;
        }
        ++ pool_y;
        pool_x = 0;
    }
}
term_t *allocate() {
    find_space();
    if (pool_y == pools.size()) {
        garbage_collect();
        if (pool_y == pools.size()) {
            size_t n = 1 << (pools.size() + 10);
            pools.push_back(make_pair(new term_t[n], n));
            for (int i = 0; i < n; ++ i) {
                pools.back().first[i] = { Free };
            }
        }
    }
    term_t *t = &pools[pool_y].first[pool_x];
    ++ pool_x;
    if (pool_x == pools[pool_y].second) {
        ++ pool_y;
        pool_x = 0;
    }
    roots.push_back(t);
    return t;
}
#endif

term_t *term(tag_t tag, term_t *x = nullptr, term_t *y = nullptr) {
#ifndef NOGC
    term_t *t = allocate();
#else
    term_t *t = new term_t;
#endif
    *t = { tag, x, y };
    return t;
}

term_t *parse(int & i, string const & t) {
    assert (i < t.length());
    char c = t[i++];
    if (c == Ap) {
        term_t *x = parse(i,t);
        term_t *y = parse(i,t);
        return term(Ap, x, y);
    } else {
        return term(tag_t(c));
    }
}
term_t *parse(string const & s) {
    string t;
    for (char c : s) {
        switch (tolower(c)) {
            case Ap: case S: case K: case I:
                t += tolower(c);
        }
    }
    if (t.empty()) return term(I);
    int i = 0;
    return parse(i,t);
}

term_t *church(int n) {
    if (n == 0) return parse("`ki");
    if (n == 1) return parse("i");
    if (n == 256) return parse("```sii```sii``s``s`kski");
    return term(Ap, parse("`s``s`ksk"), church(n-1));
}
term_t *cons(term_t *x, term_t *xs) { return term(Ap, term(Ap, parse("``s``s`ks``s`kk``s`ks``s`k`sik`kk"), x), xs); }
term_t *car(term_t *xs) { return term(Ap, parse("``si`kk"), xs); }
term_t *cdr(term_t *xs) { return term(Ap, parse("``si`k`ki"), xs); }
term_t *unchurch(term_t *x) { return term(Ap, term(Ap, x, term(Succ)), term(Num, 0) ); }

term_t *eval(term_t *t) {
    if (t->tag == Ap) {
        t = term(Ap, eval(t->x), t->y);
        switch (t->x->tag) {
            case S:
                if (t->x->x == nullptr) {
                    return term(S, t->y);
                } else if (t->x->y == nullptr) {
                    return term(S, t->x->x, t->y);
                } else {
                    return eval(term(Ap, term(Ap, t->x->x, t->y), term(Ap, t->x->y, t->y)));
                }
            case K:
                if (t->x->x == nullptr) {
                    return term(K, t->y);
                } else {
                    return eval(t->x->x);
                }
            case I:
                return eval(t->y);
            case Succ:
                t->y = eval(t->y);
                assert (t->y->tag == Num);
                return term(Num, (term_t *)(size_t(t->y->x) + 1));
            case In: {
                int c = cin.get();
                if (not cin) c = 256;
                *t->x = *cons(church(c), term(In));
                return eval(t);
            }
            default:; // nop
        }
    }
    return t;
}

int main(int argc, char **argv) {
    string code; {
        string path = argv[1];
        ifstream ifs(path);
        while (true) {
            int c = ifs.get();
            if (not ifs) break;
            code += c;
        }
    }
    term_t *prog = parse(code);
    prog = term(Ap, prog, term(In));
    while (true) {
        term_t *t = eval(unchurch(car(prog)));
        assert (t->tag == Num);
        int n = size_t(t->x);
        if (n >= 256) return n - 256;
        cout << char(n);
        prog = eval(cdr(prog));
#ifndef NOGC
        // remove all temporal objects
        roots.clear();
        roots.push_back(prog);
#endif
    }
}
```
