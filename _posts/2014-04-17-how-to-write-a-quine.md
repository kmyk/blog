---
category: blog
layout: post
date: 2014-04-17T23:44:24+09:00
tags: [ "quine" ]
---

# quineを書く一般的な方法

-   言語固有の機能を使い特殊な方法でquineする場合は考えない
-   とりあえず書ければいい人向け

<!-- more -->

## 外観
quineは

``` python
eval("program(data)") #=> "program(data)"
```

となる`program`部と`data`部に分けられる

## 詳細
`program`と`data`はたいてい以下のように動く  
python風言語で示す

``` python
.   eval("program(data)")
->  program(data)
=   print(format(str(data), repr(data)))
->  print(format("program", "data"))
->  print("program(data)")
#=> "program(data)"
```

## 実装
つまり、基本的に、実装/決定すべきは、

-   適当な入力`data`
-   変換関数`str : data -> "program"`
-   変換関数`repr : data -> "data"`
-   結合関数`format : ("program", "data") -> "program(data)"`
-   適当な出力`print`

である  
`str`,`repr`,`format`等の役割の境界は曖昧である
言語によっては`print`と`format`に`printf`を採用し1つにまとめるなどできる

これらはたいてい、

-   `data = quote("program")`
-   `str = id`
-   `repr = quote`
-   `format = append, format`
-   `print = print`

が使われる  
実装量が少なく楽だからである

また、一般的な`print`が存在しない言語では、好みの方法で出力すれば良い

## 例

### 分かりやすい例 haskell

`show`が言語内に有るので非常に楽である

``` haskell
main = putStrLn $ (\ x -> x ++ show x) "main = putStrLn $ (\\ x -> x ++ show x) "
```

-   `data = "main = putStrLn $ (\\ x -> x ++ show x) "`
-   `str = id` (省略)
-   `repr = show`
-   `format = (++)`
-   `print = putStrLn`

### 少し長い例 python

標準関数の`repr`は高機能すぎて、quineには利用できなかったので`repr`を実装  
接続には`{}`で指定して`format`を使用

``` python
#!/usr/bin/python3
show = lambda q: '"""' + q.replace('\\','\\\\').replace('\"','\\\"') + '"""'
q = """#!/usr/bin/python3
show = lambda q: '\"\"\"' + q.replace('\\\\','\\\\\\\\').replace('\\\"','\\\\\\\"') + '\"\"\"'
q = {}
print(q.format(show(q)))"""
print(q.format(show(q)))
```

### 一般的な例 lazyk (iota)
[次の記事](/blog/2014/04/17/quine-in-lazy-k/)


## 参考
-   [クワイン (プログラミング) - Wikipedia](http://ja.wikipedia.org/wiki/%E3%82%AF%E3%83%AF%E3%82%A4%E3%83%B3_\(%E3%83%97%E3%83%AD%E3%82%B0%E3%83%A9%E3%83%9F%E3%83%B3%E3%82%B0\))
-   [文字列リテラルが無いLazy Kで黒魔術も力技も使わずにクワイン - fumievalの日記](http://d.hatena.ne.jp/fumiexcel/20120402/1333343067)
