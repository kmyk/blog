---
category: blog
layout: post
title: "prologでquine書いた"
date: 2015-08-13T05:29:45+09:00
tags: [ "prolog", "quine" ]
---

``` prolog
f('\"') :- write("\\\"").
f('\\') :- write("\\\\").
f('\n') :- write("\\n").
f(X) :- write(X).
print(X) :- write('"'), string_chars(X, Y), maplist(f, Y), write('"').
main :- program(P), write(P), write("program("), print(P), write(").\n").
program("f('\\\"') :- write(\"\\\\\\\"\").\nf('\\\\') :- write(\"\\\\\\\\\").\nf('\\n') :- write(\"\\\\n\").\nf(X) :- write(X).\nprint(X) :- write('\"'), string_chars(X, Y), maplist(f, Y), write('\"').\nmain :- program(P), write(P), write(\"program(\"), print(P), write(\").\\n\").\n").
```

``` sh
$ diff <(swipl -q -t main -s quine.pdb) quine.pdb
```
