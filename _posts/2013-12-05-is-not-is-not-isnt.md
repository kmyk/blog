---
category: blog
layout: post
date: 2013-12-05T14:24:25+09:00
tags: [ "coffee" ]
---

# coffeescriptのis notとisntは違う

```coffeescript
a is not b
a isnt b
```
は

```javascript
a === !b
a !=== b
```
だそうだ  
つまり `a is not b` = `a is (not b)`

[try](http://coffeescript.org/#try:a%20is%20not%20b%0Aa%20isnt%20b)
