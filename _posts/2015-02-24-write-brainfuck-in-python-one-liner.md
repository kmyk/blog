---
category: blog
layout: post
date: 2015-02-24T18:03:42+09:00
tags: [ "python", "python3", "brainfuck", "oneliner", "lambda" ]
---

# brainfuck処理系を1行のpythonで書く

pythonの哲学は`there's only one way to do it`らしいですね。`only one way`だとか言われると`alternative way`を探したくなりますね。探しました。

``` python
(lambda let: let(__import__('sys'), lambda sys: let(lambda *xs: xs[len(xs)-1](*xs[0:len(xs)-1]), lambda let: let(lambda init, pred, val, body: let(type('loop', (object,), dict(data=init, __iter__=lambda self: self, __next__=lambda self: next(iter([])) if pred(self.data) else setattr(self,'data',body(self.data))))(), lambda loop: min(map(lambda x: 0, loop)) or val(loop.data)), lambda do: let(lambda *xs: do(*xs) if len(xs) <= 4 else let(lambda i: lambda ys: xs[len(xs)-i](*ys), lambda f: do(xs[0:len(xs)-3], f(3), f(2), f(1))), lambda do: let(open(sys.argv[1]).read(), [0]*30000, lambda code, mem: let(lambda p: do(p+1,1, lambda p,n: n == 0, lambda p,n: p,   lambda p,n: (p+1,n+{'[':1,']':-1}.get(code[p],0))), lambda to_done: let(lambda p: do(p-1,1, lambda p,n: n == 0, lambda p,n: p+2, lambda p,n: (p-1,n-{'[':1,']':-1}.get(code[p],0))), lambda to_while: do(0, 0, lambda pptr,dptr: pptr == len(code), lambda pptr,dptr: None, lambda pptr,dptr: { '+': lambda: (mem.__setitem__(dptr,(mem[dptr]+1)%256) or (pptr+1,dptr)) , '-': lambda: (mem.__setitem__(dptr,(mem[dptr]-1)%256) or (pptr+1,dptr)) , '<': lambda: (pptr+1,dptr+1) , '>': lambda: (pptr+1,dptr-1) , '.': lambda: (print(chr(mem[dptr]),end='') or (pptr+1,dptr)) , ',': lambda: let(sys.stdin.read(1), lambda c: mem.__setitem__(dptr, 0 if c == '' else ord(c)) or (pptr+1,dptr)) , '[': lambda: ((pptr+1,dptr) if mem[dptr] != 0 else (to_done(pptr), dptr)) , ']': lambda: ((pptr+1,dptr) if mem[dptr] == 0 else (to_while(pptr),dptr))}.get(code[pptr], lambda: (pptr+1,dptr))())))))))))(lambda x, f: f(x)) 
```

<!-- more -->

## 条件

-   `eval`系は当然禁止
-   `__import__`は推奨されないため必要最低限のみ

``` python
$ python --version
Python 3.4.2
```

## code

``` python
(lambda let:
    let(__import__('sys'), lambda sys:
    let(lambda *xs: xs[len(xs)-1](*xs[0:len(xs)-1]), lambda let:
    let(lambda init, pred, val, body:
        let(type('loop', (object,), dict(
            data=init,
            __iter__=lambda self: self,
            __next__=lambda self:
                next(iter([])) if pred(self.data)
                else setattr(self,'data',body(self.data))))(),
            lambda loop: min(map(lambda x: 0, loop)) or val(loop.data)), lambda do:
    let(lambda *xs: do(*xs) if len(xs) <= 4 else let(lambda i: lambda ys: xs[len(xs)-i](*ys), lambda f: do(xs[0:len(xs)-3], f(3), f(2), f(1))), lambda do:
    let(open(sys.argv[1]).read(), [0]*30000, lambda code, mem:
    let(lambda p: do(p+1,1, lambda p,n: n == 0, lambda p,n: p,   lambda p,n: (p+1,n+{'[':1,']':-1}.get(code[p],0))), lambda to_done:
    let(lambda p: do(p-1,1, lambda p,n: n == 0, lambda p,n: p+2, lambda p,n: (p-1,n-{'[':1,']':-1}.get(code[p],0))), lambda to_while:
        do(0, 0, lambda pptr,dptr: pptr == len(code), lambda pptr,dptr: None,
        lambda pptr,dptr:
            { '+': lambda: (mem.__setitem__(dptr,(mem[dptr]+1)%256) or (pptr+1,dptr))
            , '-': lambda: (mem.__setitem__(dptr,(mem[dptr]-1)%256) or (pptr+1,dptr))
            , '<': lambda: (pptr+1,dptr+1)
            , '>': lambda: (pptr+1,dptr-1)
            , '.': lambda: (print(chr(mem[dptr]),end='') or (pptr+1,dptr))
            , ',': lambda: let(sys.stdin.read(1), lambda c: mem.__setitem__(dptr, 0 if c == '' else ord(c)) or (pptr+1,dptr))
            , '[': lambda: ((pptr+1,dptr) if mem[dptr] != 0 else (to_done(pptr), dptr))
            , ']': lambda: ((pptr+1,dptr) if mem[dptr] == 0 else (to_while(pptr),dptr))
            }.get(code[pptr], lambda: (pptr+1,dptr))())
    ))))))))(lambda x, f: f(x))
```

## 参考

当然ながら先人がいました: [Brainfuck in One Line of Python](http://www.cs.princeton.edu/~ynaamad/misc/bf.htm)

brainfuckのinterpreterは適度に複雑だしbrainfuckそのものも好きなので頻繁に書くのですが、大抵誰かとかぶるのが問題ですね
