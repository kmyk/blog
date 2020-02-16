---
layout: post
redirect_from:
  - /blog/2016/05/24/anagol-hypotenuse-length/
date: 2016-05-24T23:35:20+09:00
tags: [ "golf", "writeup", "anagol", "anarch-golf", "float" ]
"target_url": [ "http://golf.shinh.org/p.rb?Hypotenuse+length" ]
---

# Anarch Golf 951. Hypotenuse length

浮動小数点数の問題は横並びになりやすい印象がある。

## c

`hypot`の有無による3Bの差と、表記のゆれを除いて皆同じコードであった。

### 76B

```
float a,b;main(){while(~scanf("%f%f",&a,&b))printf("%.2f\n",sqrt(a*a+b*b));}
```

私は`hypot`を忘れていたのでこれを提出した。

### 73B

```
float a,b;main(){while(~scanf("%f%f",&a,&b))printf("%.2f\n",hypot(a,b));}
```

`hypot`はC99で定義されている。

## perl

ほぼ皆38Bで横並び。コードもほぼ同じだが、`/ /`の位置等の細かい違いは多い。
`/ /`が`1`になることを使って`*`で潰してるのは上手いと思った。

### 38B

``` perl
/ /,printf"%.2f
",sqrt$`**2+$'**2for<>
```

## ruby

ほぼ皆38B。私のは54Bだった(省略)。
どれも`-a`で`$F`に取って`hypot(*$F)`な感じにするもの。

### ludoさん 38B

``` ruby
#!ruby -ap
$_="%.2f
"%Complex(*$F).abs
```

### mitchsさん、xsotさん 39B

``` ruby
#!ruby -na
puts'%.2f'%eval($F*'i+').abs
```

### 解説

`eval`でなく`Complex`を使ったことで1Bの差が生まれている。
`-p`と`-n`の違いによる`$_=`と`puts`の差はない。

1.8.xでは`Math.hypot(*$F)`が通る。
2.xでこれをすると`$F`の要素が`String`であるため例外が飛ぶ。

``` ruby
Complex(*$F)
eval($F*'i+')
(eval$F*'i+')

$_= + newline
puts

Complex(*$F).abs
Math.hypot(*$F)
```
