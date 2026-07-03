# UXUM examples

All examples should be built and ran from repository root.

Build:

```console
$ cargo build --workspace --all-features
```

Run one of examples:

```console
$ ./target/debug/advanced_server
```

## Example descriptions

* [`advanced_server`](advanced_server/): kitchen sink application showcasing most of `uxum`'s features.
* [`basic_server`](basic_server/): very rudimentary service provisioning. For when you don't have any time.
* [`custom_layer`](custom_layer/): example app showcasing use of custom middleware for a handler.
* [`inner_service`](inner_service/): example app to test distributed tracing.
* [`minimal`](minimal/): absolute minimum amount of code to provision axum and a simple handler.
* [`redis-kv`](redis-kv/): example made to look as a real service. can be used as a service template.
