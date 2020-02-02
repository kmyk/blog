---
category: blog
layout: post
title: "循環的にリダイレクトする"
date: 2014-07-05T20:55:05+09:00
tags: [ "stdio", "shell" ]
---

``` sh
$ tailf foo | bar >> foo
```

-   もちろん逐次処理するコマンドでないといけない
    -   例えば`sed`する時は`-u --unbuffered`optionが要るなど
    -   困ったら`while`に突っ込めば解決
-   `sh`でも可
-   `>>`を`>`にすると動いたり動かなかったりする
    -   誰か解説ください
-   例えば `$ echo > foo && tailf foo | tee >&2 | sed -ue 's/$/*/' >> foo` とかすると楽しい
