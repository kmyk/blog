# <https://kimiyuki.net>

## How to read locally

Install Ruby's [Bundler](https://bundler.io/) and run:

```console
$ bundle install --path .vendor/bundle
$ bundle exec jekyll build
```

Follow [Increasing the amount of inotify watchers](https://github.com/guard/listen/blob/master/README.md#increasing-the-amount-of-inotify-watchers) and run:

```console
$ bundle exec jekyll serve --incremental
```
