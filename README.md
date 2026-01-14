<div align="center">
  <h1>enet-dtls</h1>
  <p>
    <strong>enet fork that supports dtls</strong>
  </p>
  <p>

![MIT license](https://img.shields.io/badge/license-MIT-blue?style?style=flat-square)
  </p>
</div>

---

## Features
- openssl dtls wrapper around the enet protocol to work with the [PacketPeerDTLS](https://docs.godotengine.org/en/stable/classes/class_packetpeerdtls.html) from godot.
- only the server-side is implemented. This means `accept` works but `connect` does not.
- enforce [dtls cookies ](https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1) as per RFC 6347 to prevent UDP amplification attacks.

## Build

If included via cargo in your project, this is taken care of.

```
git submodule update --init --recursive
```

## Patched dependencies
This crate relies on a [fork](https://github.com/trimoq/enet-sys) of `enet-sys`.
Core change is a [forked](https://github.com/trimoq/enet) `enet` version that allows us to specify symbols for platform specific operations.
This allows us to hook `accept`, `send` and `receive` operations to go through openssl.

## License

Licensed under [MIT LICENSE](LICENSE) or http://opensource.org/licenses/MIT