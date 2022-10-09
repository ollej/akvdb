# akvdb

A simple key-value store with a log-structured, append-only storage
architecture where data is encrypted with AES GCM.

Modified from the actionkv example in the book
[Rust in Action](https://www.manning.com/books/rust-in-action)

Original code available here:
<https://github.com/rust-in-action/code>

## Usage

First generate an encryption key and set it in the environment variable
`AKVDB_KEY`

```bash
export AKVDB_KEY="$(./akvdb key)"
```

After that the database can be used

```bash
akvdb -d test.akv insert foo bar
akvdb -d test.akv get foo
akvdb -d test.akv update foo baz
akvdb -d test.akv get foo
akvdb -d test.akv delete foo
akvdb -d test.akv get foo
```
