---
layout: post
alias: "/blog/2016/09/05/twctf-2016-private-local-comment/"
date: "2016-09-05T14:12:19+09:00"
tags: [ "ctf", "writeup", "ppc", "mmactf", "twctf", "ruby" ]
"target_url": [ "https://score.ctf.westerns.tokyo/problems/16" ]
---

# Tokyo Westerns/MMA CTF 2nd 2016: Private / Local / Comment

Quizzes about ruby.

## Private

### Q

``` ruby
class Private
  private
  public_methods.each do |method|
    eval "def #{method.to_s};end"
  end

  def flag
    return "TWCTF{CENSORED}"
  end
end

p = Private.new
Private = nil
```

### A

Enter the scope of `p`.

``` ruby
def p.f;$><<flag;end;p.f
```

`method(:send).unbind.bind(p)[:flag]` can call the `flag` method, but it is too long ($35$ bytes).

## Local

### Q

``` ruby
def get_flag(x)
  flag = "TWCTF{CENSORED}"
  x
end
```

### A

Do tracing.

``` ruby
TracePoint.trace(:return){|a|puts a.binding.eval"flag"}
```

It may be able to get the flag with `set_trace_func`.

## Comment

### Q

``` ruby
require_relative 'comment_flag'
```

and

``` sh
$ cat comment_flag.rb
# FLAG is TWCTF{CENSORED}
```

### A

The strings of `comment_flag.rb` is loaded to the memory, and have not been garbage-collected yet.

``` ruby
ObjectSpace.each_object(String){|s|puts s if /TW+CTF/ =~ s}
```
