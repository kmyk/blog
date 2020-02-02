---
category: blog
layout: post
date: "2017-05-18T03:02:39+09:00"
title: "オンラインジャッジサーバ上でstd::threadを使う"
tags: [ "competitive", "optimization", "pthread", "elf-format" ]
---

## 背景

オンラインジャッジサービス上ではコンパイルオプションを自由に変更できない場合がある。
最適化オプションやライブラリの有無として頻繁に問題になる。
この問題の解決策のひとつとして `__libc_dlopen_mode` builtin関数などを使って実行時に陽に動的リンクすることが知られている。

しかし`std::thread`の利用の際にlibpthreadをリンクするのには注意が必要であったので書いておく。

## weak symbol

ELF formatの機能として[weak symbol](https://en.wikipedia.org/wiki/Weak_symbol)がある。
strongな(つまり通常の)symbolが定義されなかった場合にdefaultとして用いられるsymbolのことである。

`std::thread`(とそれを所持するlibstdc++)はこの機能を用いて、`std::thread`が実際に使われない限りlibpthreadをリンクしなくてもよいようにしている。
これがなければC++のプログラムは常にlibpthreadをリンクしなければならなくなってしまう。

これは`readelf`で確認すると以下のように`WEAK`となっている。

```
$ readelf -s /usr/lib/x86_64-linux-gnu/libstdc++.so.6
Symbol table '.dynsym' contains 5526 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
...
    80: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND pthread_create
...
```

これだけであれば単にダミーのsymbolを置いてリンクを通してしまえばよい。
しかし実装によってはリンク状況を確認する機能が存在する。
つまりリンカは`pthread_create`だけを要求したとしても、実行時に他の関数がリンクされていることを確認しだめなら以下のように例外を吐く。

```
terminate called after throwing an instance of 'std::system_error'
  what():  Enable multithreading to use std::thread: Operation not permitted
```

これは単に(リンカが要求した以外に)暗黙に要求されているシンボルを定義してやることで解決できる。

## 実装例

-   <https://beta.atcoder.jp/contests/abc001/submissions/1292384>
-   <http://yukicoder.me/submissions/174047>

``` c++
#include <cstdio>
#include <thread>
#include <cassert>
using ll = long long;
using namespace std;

extern "C" {
void *__libc_dlopen_mode(const char *x, int y);
void *__libc_dlsym(void *x, const char *y);
}
struct dynamic_library {
    void *handle;
    dynamic_library(string const & path) {
        int rtld_now = 2;
        handle = __libc_dlopen_mode(path.c_str(), rtld_now);
    }
    void *operator () (string const & symbol) {
        return __libc_dlsym(handle, symbol.c_str());
    }
};

const char *pthread_path = "/lib/x86_64-linux-gnu/libpthread.so.0"; // atcoder
// const char *pthread_path = "/usr/lib64/libpthread.so.0"; // yukicoder
dynamic_library pthread_handle(pthread_path);
extern "C" {
int pthread_create (pthread_t *__restrict __newthread,
        const pthread_attr_t *__restrict __attr,
        void *(*__start_routine) (void *),
        void *__restrict __arg) {
    typedef decltype(pthread_create) (*type);
    static type ptr = (type)(pthread_handle("pthread_create"));
    return ptr(__newthread, __attr, __start_routine, __arg);
}
void pthread_exit (void *__retval) {
    typedef decltype(pthread_exit) (*type);
    static type ptr = (type)(pthread_handle("pthread_exit"));
    ptr(__retval);
}
int pthread_join (pthread_t __th, void **__thread_return) {
    typedef decltype(pthread_join) (*type);
    static type ptr = (type)(pthread_handle("pthread_join"));
    return ptr(__th, __thread_return);
}
int pthread_detach (pthread_t __th) {
    typedef decltype(pthread_detach) (*type);
    static type ptr = (type)(pthread_handle("pthread_detach"));
    return ptr(__th);
}
}

constexpr int mod = 1e9+7;
void func(int l, int r, int *result) {
    ll acc = 1;
    for (int i = l; i < r; ++ i) {
        acc = acc * i % mod;
    }
    *result = acc;
}
int main() {
    int n = 1000000005;
    int result[4];
    constexpr int num_threads = 4;
    thread th[num_threads];
    for (int i = 0; i < num_threads; ++ i) {
        int l = (n - 1) *(ll)  i    / num_threads + 1;
        int r = (n - 1) *(ll) (i+1) / num_threads + 1;
        th[i] = thread(func, l, r, &result[i]);
    }
    ll acc = 1;
    for (int i = 0; i < num_threads; ++ i) {
        th[i].join();
        acc = acc * result[i] % mod;
    }
    assert (acc == 500000003);
    return 0;
}
```
