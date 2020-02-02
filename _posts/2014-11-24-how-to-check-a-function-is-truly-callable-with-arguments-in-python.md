---
category: blog
layout: post
title: "pythonで関数がある引数に対し真に呼び出し可能か判定する方法"
date: 2014-11-24T17:18:43+09:00
tags: [ "python", "type", "function" ]
---

``` python
def f(a, b, c=True):
    print(a, b, c)

f('foo')     #=> TypeError: f() missing 1 required positional argument: 'b'
f('bar', 16) #=> `bar 16 True' *side effects*

import inspect

# new in version 3.3
inspect.signature(f).bind('foo')     #=> TypeError: 'b' parameter lacking default value
inspect.signature(f).bind('bar', 16) #=> <BoundArguments object> *pure*

# new in version 2.7, 3.2
inspect.getcallargs(f, 'foo')     #=> TypeError: f() missing 1 required positional argument: 'b'
inspect.getcallargs(f, 'bar', 16) #=> {'b': 16, 'c': True, 'a': 'bar'} *pure*
```

-   <http://docs.python.jp/3/library/inspect.html#inspect.Signature.bind>
-   <http://docs.python.jp/3/library/inspect.html#inspect.getcallargs>
-   <http://docs.python.jp/2/library/inspect.html#inspect.getcallargs>
