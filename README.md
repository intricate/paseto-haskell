# paseto-haskell

A Haskell implementation of [PASETO (**P**latform-**A**gnostic **SE**curity **TO**kens)](https://paseto.io/).

## What is PASETO?

PASETO is everything you love about JOSE (JWT, JWE, JWS) without any of the [many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

## Supported PASETO Versions

|          |  v1  |  v2  |  v3  |  v4  |
| ---------| ---- | ---- | ---- | ---- |
| `local`  |  ❌  |  ❌  |  ✅  |  ✅  |
| `public` |  ❌  |  ❌  |  ✅  |  ✅  |

This library supports PASETO versions [3](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md) and [4](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md) along with both purposes (`local` and `public`).

Since versions [1](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version1.md) and [2](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version2.md) are deprecated, there is no plan to support them.
