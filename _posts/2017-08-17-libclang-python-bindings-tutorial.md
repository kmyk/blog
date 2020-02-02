---
category: blog
layout: post
date: "2017-08-17T02:37:28+09:00"
title: "libclangのPython bindingsで構文解析する"
tags: [ "clang", "python" ]
---

なんだか難しいやつという印象があったが使えば使えたので簡単にメモしておく。
githubに上げて動態保存したいところだが、用途が死んでしまったのでblogに。

## 導入

Ubuntuなら

``` sh
$ apt install python-clang-4.0 libclang-4.0-dev
```

あるいはpip <https://pypi.python.org/pypi/clang>

``` sh
$ pip2 instal clang
```

Python 3.xのは入るが動かなかった。

## 資料

コードは全て`clang/cindex.py`の中。これを読んでいい感じにすればよい。
手元では特に [/usr/lib/python2.7/dist-packages/clang/cindex.py](file:///usr/lib/python2.7/dist-packages/clang/cindex.py) に位置していた。

公式のdocumentはこれ: <http://releases.llvm.org/4.0.0/tools/clang/docs/index.html>

その他の資料としては:

-   <http://eli.thegreenplace.net/2011/07/03/parsing-c-in-python-with-clang>
-   <http://asdm.hatenablog.com/entry/2015/01/08/170707>
-   <http://d.hatena.ne.jp/osyo-manga/searchdiary?word=%2A%5Bclang%5D>

## 概要

登場するclassについて

-   `Index`
    -   なんか top-level なやつ、`libclang-x.y.so` を保持するぐらいの役割
-   `TranslationUnit`
    -   構文解析結果の木をまとめたもの
    -   `index.parse(...)`により作られる
-   `Cursor`
    -   木の頂点を指す
    -   `tu.cursor`で得られる
    -   `cursor.get_children()`で子を取得し再帰する
    -   `cursor.kind`で`CursorKind.FUNCTION_DECL`だとかそういう情報が取れる

## 具体例

まず`Index`の作成。これはすぐ。

``` python
# Python Version: 2.x
from clang.cindex import Index
index = Index.create()
```

次に`TranslationUnit`を作る。コードを持ってきて解析させる。コンパイル時オプションを渡したり出力される警告やエラーを受け取ったりもできる。

``` python
path = 'foo.cpp'
code = '''\
#include <iostream>
using namespace std;
int main() {
    cout << hello + world << endl;
    return 0;
}
'''
tu = index.parse(path, unsaved_files=[ (path, code) ], args=[ '-std=c++14' ])
```

そして`Cursor`で木を舐める。
普通にやるだけ。
例えば以下のようにすると、`iostream`をincludeすることで定義される構造体/classが列挙される。

``` python
from clang.cindex import CursorKind
namespace = []
def visit(cursor):
    global namespace
    if cursor.kind == CursorKind.TRANSLATION_UNIT:
        for child in cursor.get_children():
            visit(child)
    elif cursor.kind == CursorKind.NAMESPACE:
        namespace += [ cursor.spelling ]
        for child in cursor.get_children():
            visit(child)
        namespace.pop()
    elif cursor.kind in ( CursorKind.STRUCT_DECL, CursorKind.CLASS_DECL, CursorKind.CLASS_TEMPLATE, ):
        if cursor.spelling.strip() and not cursor.spelling.startswith('_'):
            print '::'.join(namespace + [ cursor.spelling ])  #=> std::allocator std::uses_allocator std::char_traits std::__cxx11::basic_string ...
    else:
        pass
visit(tu.cursor)
```
