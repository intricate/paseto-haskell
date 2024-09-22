{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

-- | PASETO token encoding and decoding in accordance with the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
module Crypto.Paseto.Token.Encoding
  ( -- * Encoding
    encode
  , encodeSomeToken

    -- * Decoding
  , CommonDecodingError (..)
  , renderCommonDecodingError
  , V3LocalDecodingError (..)
  , renderV3LocalDecodingError
  , decodeTokenV3Local
  , V3PublicDecodingError (..)
  , renderV3PublicDecodingError
  , decodeTokenV3Public
  , V4LocalDecodingError (..)
  , renderV4LocalDecodingError
  , decodeTokenV4Local
  , V4PublicDecodingError (..)
  , renderV4PublicDecodingError
  , decodeTokenV4Public

    -- * Validated token
  , ValidatedToken (..)
  ) where

import Crypto.Paseto.Keys ( SymmetricKey (..), VerificationKey (..) )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import qualified Crypto.Paseto.Protocol.V3 as V3
import qualified Crypto.Paseto.Protocol.V4 as V4
import Crypto.Paseto.Token
  ( Footer (..), ImplicitAssertion, Payload (..), SomeToken (..), Token (..) )
import Crypto.Paseto.Token.Claims ( Claims )
import Crypto.Paseto.Token.Parser
  ( parseTokenV3Local
  , parseTokenV3Public
  , parseTokenV4Local
  , parseTokenV4Public
  )
import Crypto.Paseto.Token.Validation
  ( ValidationError, ValidationRule, renderValidationErrors, validate )
import Data.Bifunctor ( first )
import qualified Data.ByteString.Base64.URL as B64URL
import Data.List.NonEmpty ( NonEmpty )
import Data.Text ( Text )
import qualified Data.Text as T
import Data.Text.Encoding ( decodeUtf8 )
import Prelude
import Text.Parsec ( ParseError )

-- | Encode a PASETO token as human-readable text according to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
encode :: Token v p -> Text
encode t =
  case t of
    TokenV3Local (Payload payload) mbFooter ->
      decodeUtf8 V3.v3LocalTokenHeader
        <> decodeUtf8 (B64URL.encodeUnpadded payload)
        <> case mbFooter of
          Nothing -> ""
          Just (Footer footer) -> "." <> decodeUtf8 (B64URL.encodeUnpadded footer)
    TokenV3Public (Payload payload) mbFooter ->
      decodeUtf8 V3.v3PublicTokenHeader
        <> decodeUtf8 (B64URL.encodeUnpadded payload)
        <> case mbFooter of
          Nothing -> ""
          Just (Footer footer) -> "." <> decodeUtf8 (B64URL.encodeUnpadded footer)
    TokenV4Local (Payload payload) mbFooter ->
      decodeUtf8 V4.v4LocalTokenHeader
        <> decodeUtf8 (B64URL.encodeUnpadded payload)
        <> case mbFooter of
          Nothing -> ""
          Just (Footer footer) -> "." <> decodeUtf8 (B64URL.encodeUnpadded footer)
    TokenV4Public (Payload payload) mbFooter ->
      decodeUtf8 V4.v4PublicTokenHeader
        <> decodeUtf8 (B64URL.encodeUnpadded payload)
        <> case mbFooter of
          Nothing -> ""
          Just (Footer footer) -> "." <> decodeUtf8 (B64URL.encodeUnpadded footer)

-- | Encode a PASETO token as human-readable text according to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
encodeSomeToken :: SomeToken -> Text
encodeSomeToken t =
  case t of
    SomeTokenV3Local x -> encode x
    SomeTokenV3Public x -> encode x
    SomeTokenV4Local x -> encode x
    SomeTokenV4Public x -> encode x

-- | PASETO token which has been decoded and validated.
data ValidatedToken v p = ValidatedToken
  { -- | Validated token.
    vtToken :: !(Token v p)
  , -- | Validated token's claims.
    vtClaims :: !Claims
  } deriving stock (Show, Eq)

-- | Common error decoding a PASETO token.
data CommonDecodingError
  = -- | Error parsing the token.
    CommonDecodingParseError !ParseError
  | -- | Token claims validation error.
    CommonDecodingClaimsValidationError !(NonEmpty ValidationError)
  deriving stock (Show, Eq)

-- | Render a 'CommonDecodingError' as 'Text'.
renderCommonDecodingError :: CommonDecodingError -> Text
renderCommonDecodingError err =
  case err of
    CommonDecodingParseError e -> T.pack (show e)
    CommonDecodingClaimsValidationError e -> renderValidationErrors e

assertValid :: [ValidationRule] -> Claims -> Either CommonDecodingError ()
assertValid rs cs =
  case validate rs cs of
    Left err -> Left (CommonDecodingClaimsValidationError err)
    Right _ -> Right ()

-- | Error decoding a version 3 local PASETO token.
data V3LocalDecodingError
  = -- | Common decoding error.
    V3LocalDecodingCommonError !CommonDecodingError
  | -- | Decryption error.
    V3LocalDecodingDecryptionError !V3.DecryptionError
  deriving stock (Show, Eq)

-- | Render a 'V3LocalDecodingError' as 'Text'.
renderV3LocalDecodingError :: V3LocalDecodingError -> Text
renderV3LocalDecodingError err =
  case err of
    V3LocalDecodingCommonError e -> renderCommonDecodingError e
    V3LocalDecodingDecryptionError e -> V3.renderDecryptionError e

-- | Parse, 'V3.decrypt', and 'validate' a version 3 local PASETO token.
decodeTokenV3Local
  :: SymmetricKey V3
  -- ^ Symmetric key.
  -> [ValidationRule]
  -- ^ Validation rules.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Text
  -- ^ Encoded PASETO token.
  -> Either V3LocalDecodingError (ValidatedToken V3 Local)
decodeTokenV3Local k rs f i t = do
  parsed <-
    first
      (V3LocalDecodingCommonError . CommonDecodingParseError)
      (parseTokenV3Local t)
  claims <-
    case V3.decrypt k parsed f i of
      Left err -> Left (V3LocalDecodingDecryptionError err)
      Right x -> Right x
  first V3LocalDecodingCommonError (assertValid rs claims)
  Right ValidatedToken
    { vtToken = parsed
    , vtClaims = claims
    }

-- | Error decoding a version 3 public PASETO token.
data V3PublicDecodingError
  = -- | Common decoding error.
    V3PublicDecodingCommonError !CommonDecodingError
  | -- | Cryptographic signature verification error.
    V3PublicDecodingVerificationError !V3.VerificationError
  deriving stock (Show, Eq)

-- | Render a 'V3PublicDecodingError' as 'Text'.
renderV3PublicDecodingError :: V3PublicDecodingError -> Text
renderV3PublicDecodingError err =
  case err of
    V3PublicDecodingCommonError e -> renderCommonDecodingError e
    V3PublicDecodingVerificationError e -> V3.renderVerificationError e

-- | Parse, 'V3.verify', and 'validate' a version 3 public PASETO token.
decodeTokenV3Public
  :: VerificationKey V3
  -- ^ Verification key.
  -> [ValidationRule]
  -- ^ Validation rules.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Text
  -- ^ Encoded PASETO token.
  -> Either V3PublicDecodingError (ValidatedToken V3 Public)
decodeTokenV3Public vk rs f i t = do
  parsed <-
    first
      (V3PublicDecodingCommonError . CommonDecodingParseError)
      (parseTokenV3Public t)
  claims <-
    case V3.verify vk parsed f i of
      Left err -> Left (V3PublicDecodingVerificationError err)
      Right x -> Right x
  first V3PublicDecodingCommonError (assertValid rs claims)
  Right ValidatedToken
    { vtToken = parsed
    , vtClaims = claims
    }

-- | Error decoding a version 4 local PASETO token.
data V4LocalDecodingError
  = -- | Common decoding error.
    V4LocalDecodingCommonError !CommonDecodingError
  | -- | Decryption error.
    V4LocalDecodingDecryptionError !V4.DecryptionError
  deriving stock (Show, Eq)

-- | Render a 'V4LocalDecodingError' as 'Text'.
renderV4LocalDecodingError :: V4LocalDecodingError -> Text
renderV4LocalDecodingError err =
  case err of
    V4LocalDecodingCommonError e -> renderCommonDecodingError e
    V4LocalDecodingDecryptionError e -> V4.renderDecryptionError e

-- | Parse, 'V4.decrypt', and 'validate' a version 4 local PASETO token.
decodeTokenV4Local
  :: SymmetricKey V4
  -- ^ Symmetric key.
  -> [ValidationRule]
  -- ^ Validation rules.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Text
  -- ^ Encoded PASETO token.
  -> Either V4LocalDecodingError (ValidatedToken V4 Local)
decodeTokenV4Local k rs f i t = do
  parsed <-
    first
      (V4LocalDecodingCommonError . CommonDecodingParseError)
      (parseTokenV4Local t)
  claims <-
    case V4.decrypt k parsed f i of
      Left err -> Left (V4LocalDecodingDecryptionError err)
      Right x -> Right x
  first V4LocalDecodingCommonError (assertValid rs claims)
  Right ValidatedToken
    { vtToken = parsed
    , vtClaims = claims
    }

-- | Error decoding a version 4 public PASETO token.
data V4PublicDecodingError
  = -- | Common decoding error.
    V4PublicDecodingCommonError !CommonDecodingError
  | -- | Cryptographic signature verification error.
    V4PublicDecodingVerificationError !V4.VerificationError
  deriving stock (Show, Eq)

-- | Render a 'V4PublicDecodingError' as 'Text'.
renderV4PublicDecodingError :: V4PublicDecodingError -> Text
renderV4PublicDecodingError err =
  case err of
    V4PublicDecodingCommonError e -> renderCommonDecodingError e
    V4PublicDecodingVerificationError e -> V4.renderVerificationError e

-- | Parse, 'V4.verify', and 'validate' a version 4 public PASETO token.
decodeTokenV4Public
  :: VerificationKey V4
  -- ^ Verification key.
  -> [ValidationRule]
  -- ^ Validation rules.
  -> Maybe Footer
  -- ^ Optional footer to authenticate.
  -> Maybe ImplicitAssertion
  -- ^ Optional implicit assertion to authenticate.
  -> Text
  -- ^ Encoded PASETO token.
  -> Either V4PublicDecodingError (ValidatedToken V4 Public)
decodeTokenV4Public vk rs f i t = do
  parsed <-
    first
      (V4PublicDecodingCommonError . CommonDecodingParseError)
      (parseTokenV4Public t)
  claims <-
    case V4.verify vk parsed f i of
      Left err -> Left (V4PublicDecodingVerificationError err)
      Right x -> Right x
  first V4PublicDecodingCommonError (assertValid rs claims)
  Right ValidatedToken
    { vtToken = parsed
    , vtClaims = claims
    }
