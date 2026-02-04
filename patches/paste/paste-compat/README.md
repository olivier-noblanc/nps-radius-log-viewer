# Pastey Compatibility with Paste

Pastey is meant to be a drop-in replacement for paste crate while also provinding bug fixes and more
features. The `pastey` crate has provided some new modifers without touching the exising behaviour.

This directory has certain test cases which are taken from [dtolnay/paste] and should be same with
pastey crate. You are always welcome to add new test cases, but this test case is isolated from
the main pastey test case to ensure, these tests are modified and accidently introduce breaking changes.

## Running tests

To run the test, use `./test.sh`, it will fail if pastey doesn't behave like paste crate.

[dtolnay/paste]: https://github.com/dtolnay/paste
