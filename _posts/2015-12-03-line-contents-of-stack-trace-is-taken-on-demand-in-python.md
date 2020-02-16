---
category: blog
layout: post
date: 2015-12-03T13:27:31+09:00
tags: [ "python", "debug", "stacktrace" ]
---

# pythonのstacktraceで表示される行の内容は毎回その場で取得されているという話

条件が揃うと、以下のようなstacktraceが表示されて混乱が生じる。
`print('yeah')`の行で`ZeroDivisionError`が発生しているように見えて困る。

``` python
>>> foo.foo()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/path/to/foo.py", line 3, in foo
    bar.bar()
  File "/path/to/bar.py", line 2, in bar
    print('yeah')
ZeroDivisionError: division by zero
```

友人が踏んで、私も見てみてしばらく分からなかった。
ちょっと面白かったので書いた。

<!-- more -->

## 再現

``` python
$ cat foo.py
import bar
def foo():
    bar.bar()
$ cat bar.py
def bar():
    0/0
$ python --version
Python 3.5.0
$ python
>>> import foo
>>> foo.foo()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/path/to/foo.py", line 3, in foo
    bar.bar()
  File "/path/to/bar.py", line 2, in bar
    0/0
ZeroDivisionError: division by zero
>>> ^Z
$ vim bar.py
$ cat bar.py
def bar():
    0/0
    print('yeah')
$ fg
>>> foo.foo()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/path/to/foo.py", line 3, in foo
    bar.bar()
  File "/path/to/bar.py", line 2, in bar
    print('yeah')
ZeroDivisionError: division by zero
```

## 他

-   混乱を招くかもしれないが、まあ仕様の範疇だろう。
-   `imp.reload(bar)`として`bar`moduleを読み込み直せば解消される。`import bar`や`imp.reload(foo)`ではだめなことに注意。
-   2でも3でも発生する。
-   rubyでは、そもそも行の内容が表示されないので発生しなかった。

``` ruby
irb(main):008:0> foo()
ZeroDivisionError: divided by 0
        from /path/to/bar.rb:2:in `/'
        from /path/to/bar.rb:2:in `bar'
        from /path/to/foo.rb:3:in `foo'
        from (irb):8
        from /usr/bin/irb:11:in `<main>'
```
