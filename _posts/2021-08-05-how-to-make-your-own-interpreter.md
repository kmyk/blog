---
category: blog
layout: post
---

# プログラミング言語処理系の作り方 (競プロer向け)

## TL;DR

-   プログラミング言語処理系は競プロer ならパソコン知識がなくてもやるだけで作れる

## はじめに

最近、競プロ界隈で言語処理系の製作が流行っている気がします。
[LayCurse](https://atcoder.jp/users/LayCurse) さんの [cLay](http://rsujskf.s602.xrea.com/?cLay) は古くからありますが、最近新しく [niuez](https://atcoder.jp/users/niuez) さんの [Niu](https://github.com/niuez/Niu) や [colun](https://atcoder.jp/users/colun) さんの [mmlang](https://github.com/colun/mmlang) などが登場しました。
私も [Jikka](https://github.com/kmyk/Jikka) という処理系を作っています。
他にも、まだ未公開のようですが、言語処理系を作っているらしき人を何人か見かけています。

しかし「処理系はどのようにすれば作れるか」や「処理系はどの部分がどのくらい難しいのか」についてはほとんど知られていないように見えます。
たとえば、純粋培養の競プロerにとっては「web アプリを作る」よりも「言語処理系を作る」ことの方がはるかに簡単だと私は思っているのですが、そのように理解している競プロerは少ないように見えます。
そこで、この記事はこれらのことを説明します。

## 処理のおおまかな流れ

競プロ関係の言語処理系を書くとなると、その処理は以下のような流れになるでしょう。

1. 構文解析
2. 変換
3. 出力

まず入力言語 (C++ や Python などあるいは独自言語) のソースコード (文字列) を受けとり、これを構文解析して抽象構文木 (木構造) に変換します。
抽象構文木上で最適化などの変換を好きなだけ行い、そして出力言語 (C++ や Python などあるいはアセンブリ言語や機械語) に変換して出力します。

入力も出力もただの文字列であり、「ネットワーク」だとか「データベース」だとかのパソコン要素は一切含まれていないことに注意してください。

## 1. 構文解析

やるだけゲーです。
ICPC でも頻繁に出題されています。
もしよく分からないという人がいれば、draftcode さんの[構文解析 Howto](https://gist.github.com/draftcode/1357281) や MAXIMUM の[構文解析 - アルゴリズム講習会](https://dai1741.github.io/maximum-algo-2012/docs/parsing/)などを読んで復習してください。

いくらやるだけとはいえ再帰下降型構文解析の手書きは面倒すぎてやりたくないという人は、[lex](https://ja.wikipedia.org/wiki/Lex) と [yacc](https://ja.wikipedia.org/wiki/Yacc) のようなパーサジェネレータや [Parsec](https://en.wikipedia.org/wiki/Parsec_(parser)) のようなパーサコンビネータを使うとよいでしょう。
これらは BNF を与えると自動で構文解析をやってくれます。

### BNF の例

たとえば C++ をかなり制限したような言語であれば以下のような [BNF](https://ja.wikipedia.org/wiki/%E3%83%90%E3%83%83%E3%82%AB%E3%82%B9%E3%83%BB%E3%83%8A%E3%82%A6%E3%82%A2%E8%A8%98%E6%B3%95) になるでしょう。

```
<program> ::= "int" "main" "(" ")" "{" <statements> "}"

<statements> ::= /* empty */
               | <statement> <statements>

<statement> ::= "int" <variable> "=" <expr> ";"
              | <variable> "=" <expr> ";"
              | "if" "(" <condition> ")" "{" <statements> "}"
              | "if" "(" <condition> ")" "{" <statements> "}" "else" "{" <statements> "}"
              | "for" "(" "int" <variable> "=" <expr> ";" <condition> ";" <expr> ")" "{" <statements> "}"
              | "return" <expr> ";"

<condition> ::= <expr> "==" <expr>
              | <expr> "!=" <expr>
              | <expr> "<" <expr>
              | <expr> "<=" <expr>

<expr> ::= <expr_a>

<expr_a> ::= <expr_m>
           | <expr_a> "+" <expr_m>
           | <expr_a> "-" <expr_m>

<expr_m> ::= <expr_u>
           | <expr_m> "*" <expr_u>

<expr_u> ::= <expr_p>
           | "+" <expr_u>
           | "-" <expr_u>

<expr_p> ::= <variable>
           | <number>
           | "(" <expr> ")"

<variable> ::= "a" | "b" | "c" | ... | "z"

<number> ::= "0" | "1" | "2" | ...
```

## 2. 変換

好きに変換をかけてください。
単純な最適化をいくつかするだけなどであれば簡単です。
一方で、C++ を機械語にしたり高度な最適化をしたりのようなギャップの大きな変換は、面倒なだけでなく理論的に難しい (そして面白い) です。

### 単純な最適化の例

変換のうちでとても簡単なものの例として、たとえば C++ のような言語で $\sum _ {i = 0} ^ {n - 1} i$ というループを閉じた式 $\frac{n (n - 1)}{2}$ に潰すような最適化を考えてみましょう。
次のようなコードがあるとしましょう:

``` c++
int main() {
    int a = 0;
    for (int i = 0; i < n; ++ i) {
        a += i;
    }
    return a;
}
```

これを次のようなコードに変換します:

``` c++
int main() {
    int a = 0;
    a = a + n * (n - 1) / 2;
    return a;
}
```

これらは抽象構文木としては、たとえば次のようなものが入力です:

![](/assets/img/how-to-make-your-own-interpreter/before.svg)

次のようなものが出力となります:

![](/assets/img/how-to-make-your-own-interpreter/after.svg)

つまり、このような木の書き換えをやればよいです。
これは「根付き木が与えられる。特定のパターンにマッチする部分木を探し、関連する別の木で置き換えよ」という問題を解くことと同値です。

## 3. 出力

やるだけです (2)。
抽象構文木を文字列に変換するような処理を書けばよいです。
これはいわゆる「木 DP」の例です。

インデントなどの見た目をきれいに整える処理は [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html) や [`yapf`](https://github.com/google/yapf) のようなフォーマッタに任せてしまうこともできます。

## まとめ

言語処理系は 1. 構文解析、2. 変換、3. 出力 をこの順に行うものでした。
見てきたように、それぞれ「ICPC でよくあるやつ」「根付き木の変形」「木 DP して文字列にするだけ」です。
つまり、難しい変換をしようとした場合を除いて、どのパートも競プロer にとってはただやるだけ (ただし面倒ではある) です。

言語処理系製作をする競プロer がさらに増えることを期待しています。

## 付録: Python から Python へのトランスパイラ

例として [`ast` module](https://docs.python.org/ja/3/library/ast.html) を用いた Python から Python への小さな最適化変換器のコードを載せておきます。
これは `for i in range(n): a += i` という形のループを探して `a += n * (n - 1) // 2` で置き換えるという最適化をし、それ以外はなにもしないようなものです。

なお、Python と [`ast` module](https://docs.python.org/ja/3/library/ast.html) を用いたのはただ私が記事を書くにあたって面倒パートを省略するためのものであり、面倒をやりさえすればすべて C++ で書いてしまうこともできるということには注意してください。

### コード

``` python
#!/usr/bin/env python3
import ast
import copy
import sys
if sys.version_info < (3, 9):
    import astor  # $ pip3 install astor==0.8.1


def optimize(node: ast.AST) -> ast.AST:
    node = copy.copy(node)
    if isinstance(node, ast.Module):
        for i in range(len(node.body)):
            node.body[i] = optimize(node.body[i])
    elif isinstance(node, ast.FunctionDef):
        for i in range(len(node.body)):
            node.body[i] = optimize(node.body[i])
    elif isinstance(node, ast.For):
        for i in range(len(node.body)):
            node.body[i] = optimize(node.body[i])

        # `for i in range(n): a += i` を `a += i * (i - 1) / 2` にする
        if isinstance(node.iter, ast.Call) and node.iter.func.id == 'range' and len(node.iter.args) == 1:
            if len(node.body) == 1 and isinstance(node.body[0], ast.AugAssign) and isinstance(node.body[0].op, ast.Add):
                if isinstance(node.body[0].value, ast.Name) and node.body[0].value.id == node.target.id:
                    n = node.iter.args[0]
                    node = node.body[0]
                    node.value = ast.BinOp(ast.BinOp(n, ast.Mult(), ast.BinOp(n, ast.Sub(), ast.Constant(1))), ast.FloorDiv(), ast.Constant(2))

    elif isinstance(node, ast.If):
        for i in range(len(node.body)):
            node.body[i] = optimize(node.body[i])
    return node


def main():
    # 1. 構文解析
    input_str = sys.stdin.read()
    input_ast = ast.parse(input_str)

    # 2. 変換
    print('#', ast.dump(input_ast))  # デバッグ用
    output_ast = optimize(input_ast)
    print('#', ast.dump(output_ast))  # デバッグ用

    # 3. 出力
    if sys.version_info < (3, 9):
        output_str = astor.to_source(output_ast)
    else:
        output_str = ast.unparse(output_ast)
    print(output_str)


if __name__ == '__main__':
    main()
```

### 実行例

``` console
$ python3 --version
Python 3.8.10

$ pip3 install astor

$ pip3 list | grep astor
astor                           0.8.1

$ cat example.py
def func(n: int) -> int:
    a: int = 0
    for i in range(n):
        a += i
    return a

$ python3 main.py < example.py
# Module(body=[FunctionDef(name='func', args=arguments(posonlyargs=[], args=[arg(arg='n', annotation=Name(id='int', ctx=Load()), type_comment=None)], vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]), body=[AnnAssign(target=Name(id='a', ctx=Store()), annotation=Name(id='int', ctx=Load()), value=Constant(value=0, kind=None), simple=1), For(target=Name(id='i', ctx=Store()), iter=Call(func=Name(id='range', ctx=Load()), args=[Name(id='n', ctx=Load())], keywords=[]), body=[AugAssign(target=Name(id='a', ctx=Store()), op=Add(), value=Name(id='i', ctx=Load()))], orelse=[], type_comment=None), Return(value=Name(id='a', ctx=Load()))], decorator_list=[], returns=Name(id='int', ctx=Load()), type_comment=None)], type_ignores=[])
# Module(body=[FunctionDef(name='func', args=arguments(posonlyargs=[], args=[arg(arg='n', annotation=Name(id='int', ctx=Load()), type_comment=None)], vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]), body=[AnnAssign(target=Name(id='a', ctx=Store()), annotation=Name(id='int', ctx=Load()), value=Constant(value=0, kind=None), simple=1), AugAssign(target=Name(id='a', ctx=Store()), op=Add(), value=BinOp(left=BinOp(left=Name(id='n', ctx=Load()), op=Mult(), right=BinOp(left=Name(id='n', ctx=Load()), op=Sub(), right=Constant(value=1))), op=FloorDiv(), right=Constant(value=2))), Return(value=Name(id='a', ctx=Load()))], decorator_list=[], returns=Name(id='int', ctx=Load()), type_comment=None)], type_ignores=[])
def func(n: int) ->int:
    a: int = 0
    a += n * (n - 1) // 2
    return a
```
