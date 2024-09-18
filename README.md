# paseto-haskell

A Haskell implementation of
[PASETO (**P**latform-**A**gnostic **SE**curity **TO**kens)](https://paseto.io/).

## What is PASETO?

PASETO is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).

## Supported PASETO Versions

|          |  v1  |  v2  |  v3  |  v4  |
| ---------| ---- | ---- | ---- | ---- |
| `local`  |  ❌  |  ❌  |  ✅  |  ✅  |
| `public` |  ❌  |  ❌  |  ✅  |  ✅  |

This library supports PASETO versions
[3](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version3.md)
and
[4](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version4.md)
along with both purposes (`local` and `public`).

Since versions
[1](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version1.md)
and
[2](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/01-Protocol-Versions/Version2.md)
are deprecated, there is no plan to support them.

## Usage

For most use cases, it should be sufficient to import the `Crypto.Paseto`
module, which just re-exports types and functions from other modules
under `Crypto.Paseto.*`.

However, there are some types and functions which aren't re-exported. So, if
you need access to any of those, you can import them from their respective
modules under `Crypto.Paseto.*`.

### Generating keys

```haskell
-- Generate symmetric keys
symmetricKeyV3 <- generateSymmetricKeyV3
symmetricKeyV4 <- generateSymmetricKeyV4

-- Generate signing keys
signingKeyV3 <- generateSigningKeyV3
signingKeyV4 <- generateSigningKeyV4

-- Construct verification keys from signing keys
verificationKeyV3 <- fromSigningKey signingKeyV3
verificationKeyV4 <- fromSigningKey signingKeyV4
```

### Building tokens

Example of building a V3 public PASETO token with some default claims:

```haskell
-- Read the signing key from a file
signingKeyBs <- BS.readFile "./signing-key-v3.bin"
signingKey <-
  case bytesToSigningKeyV3 signingKeyBs of
    Left err -> error "invalid signing key"
    Right key -> pure key

-- Get some default parameters for building the token
defaultParams <- getDefaultBuildTokenParams

-- Add a footer and implicit assertion to the build parameters
let params =
      defaultParams
        { btpFooter = Footer "1337 footer"
        , btpImplicitAssertion = ImplicitAssertion "1337 implicit assertion"
        }

-- Build the token
buildResult <- runExceptT (buildTokenV3Public params signingKey)

case buildResult of
  Left err -> error "failed to build token"
  Right token -> ...
```

With the default build parameters, this token will have the following claims:

- An `exp` claim of 1 hour from the current system time.
- An `iat` claim of the current system time.
- A `nbf` claim of the current system time.

### Decoding tokens

Example of decoding a V4 local PASETO token:

```haskell
-- Get some default validation rules
defaultRules <- getDefaultValidationRules

-- Add another validation rule to check that the token issuer is
-- "paragonie.com"
let rules :: [ValidationRules]
    rules = issuedBy (Issuer "paragonie.com") : defaultRules

-- Decode, cryptographically verify, and validate the token
let decodeResult =
      decodeAndValidateTokenV4Local
        symmetricKey
        rules
        (Just $ Footer "footer")
        Nothing -- no implicit assertion
        tokenTxt

case decodeResult of
  Left err -> error "invalid token"
  Right ValidatedToken { vtToken, vtClaims } -> ...
```

### Claims

The `Claims` container API is not re-exported from `Crypto.Paseto` since it
contains functions which may conflict with those in `Prelude` and other
container implementations such as `Data.Map`.

So you'll need to import:

```haskell
-- It isn't necessary for this to be qualified; just a recommendation.
import qualified Crypto.Paseto.Token.Claims as Claims
```

#### Constructing claims

```haskell
-- Empty collection of claims
Claims.empty

-- Collection of claims consisting of a single element
Claims.singleton (IssuerClaim $ Issuer "paragonie.com")

-- Constructing a collection of claims from a list
Claims.fromList
  [ IssuerClaim (Issuer "paragonie.com")
  , SubjectClaim (Subject "test")
  , TokenIdentifierClaim (TokenIdentifier "87IFSGFgPNtQNNuw0AtuLttPYFfYwOkjhqdWcLoYQHvL")
  ]

-- Inserting a claim into an existing collection of claims
Claims.insert (SubjectClaim $ Subject "subject") claims
```

#### Querying claims

```haskell
-- For example, looking up the issuer claim
case Claims.lookupIssuer claims of
  Nothing -> error "issuer claim does not exist"
  Just issuer -> ...
```

#### Custom claims

It's also possible to construct custom claims (i.e. claims that are not
[registered/reserved for use within PASETO](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/02-Implementation-Guide/04-Claims.md#registered-claims)).

Note that it's acceptable to store any kind of JSON data within a custom
claim.

```haskell
-- Construct the custom claim's key
customClaimKey <-
  case mkUnregisteredClaimKey "customData" of
    Nothing -> error "invalid custom claim key"
    Just k -> pure k

-- Construct the custom claim
let customClaim :: Claim
    customClaim = CustomClaim customClaimKey (Aeson.String "customValue")

-- Now you can utilize it like any other 'Claim'. For example:
let claims :: Claims
    claims = Claims.singleton customClaim
```

If you attempt to pass a registered/reserved claim key to
`mkUnregisteredClaimKey`, it will return `Nothing`:

```haskell
-- For example, this will return 'Nothing':
mkUnregisteredClaimKey "iss"
```

### Validation

As seen in the [token decoding example above](#decoding-tokens), you can
construct a list of recommended default validation rules using
`getDefaultValidationRules`. At the moment, the default rules check that:

- The `exp` claim is not in the past.
- The `iat` claim is not in the future.
- The `nbf` claim is not in the future.

There are also some other simple pre-defined rules that you can utilize. For
example:

- `forAudience`
- `identifiedBy`
- `issuedBy`
- `notExpired`
- `subject`
- `validAt`

If this is insufficient for your use case, you can also construct your own
custom validation rules:

```haskell
let f :: Claims -> Either ValidationError ()
    f claims =
      if isSomethingValid claims
        then Right ()
        else Left (ValidationCustomError "something was invalid, bro")

    customRule :: ValidationRule
    customRule = ValidationRule f
```
