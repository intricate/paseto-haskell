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
  , V3LocalDecodingError (..)
  , decodeTokenV3Local
  , V3PublicDecodingError (..)
  , decodeTokenV3Public
  , V4LocalDecodingError (..)
  , decodeTokenV4Local
  , V4PublicDecodingError (..)
  , decodeTokenV4Public

    -- * Validated token
  , ValidatedToken (..)
  ) where

import Crypto.Paseto.Keys ( SymmetricKey (..), VerificationKey (..) )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import qualified Crypto.Paseto.Protocol.V3 as V3
import qualified Crypto.Paseto.Protocol.V4 as V4
import Crypto.Paseto.Token
  ( Footer (..)
  , ImplicitAssertion
  , Payload (..)
  , SomeToken (..)
  , Token (..)
  , tokenPurpose
  , tokenVersion
  )
import Crypto.Paseto.Token.Claims ( Claims )
import Crypto.Paseto.Token.Parser ( parseSomeToken )
import Crypto.Paseto.Token.Validation
  ( ValidationError, ValidationRule, validate )
import Data.Bifunctor ( first )
import qualified Data.ByteString.Base64.URL as B64URL
import Data.List.NonEmpty ( NonEmpty )
import Data.Text ( Text )
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
  | -- | Token version and purpose is invalid.
    CommonDecodingInvalidVersionAndPurposeError
      -- | Expected token version and purpose.
      !(Version, Purpose)
      -- | Actual token version and purpose.
      !(Version, Purpose)
  | -- | Token claims validation error.
    CommonDecodingClaimsValidationError !(NonEmpty ValidationError)
  deriving stock (Show, Eq)

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
    case parseSomeToken t of
      Right (SomeTokenV3Local x) -> Right x
      Right x ->
        Left . V3LocalDecodingCommonError $
          CommonDecodingInvalidVersionAndPurposeError
            (V3, Local)
            (tokenVersion x, tokenPurpose x)
      Left err -> Left (V3LocalDecodingCommonError $ CommonDecodingParseError err)
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
    case parseSomeToken t of
      Right (SomeTokenV3Public x) -> Right x
      Right x ->
        Left . V3PublicDecodingCommonError $
          CommonDecodingInvalidVersionAndPurposeError
            (V3, Public)
            (tokenVersion x, tokenPurpose x)
      Left err -> Left (V3PublicDecodingCommonError $ CommonDecodingParseError err)
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
    case parseSomeToken t of
      Right (SomeTokenV4Local x) -> Right x
      Right x ->
        Left . V4LocalDecodingCommonError $
          CommonDecodingInvalidVersionAndPurposeError
            (V4, Local)
            (tokenVersion x, tokenPurpose x)
      Left err -> Left (V4LocalDecodingCommonError $ CommonDecodingParseError err)
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
    case parseSomeToken t of
      Right (SomeTokenV4Public x) -> Right x
      Right x ->
        Left . V4PublicDecodingCommonError $
          CommonDecodingInvalidVersionAndPurposeError
            (V4, Public)
            (tokenVersion x, tokenPurpose x)
      Left err -> Left (V4PublicDecodingCommonError $ CommonDecodingParseError err)
  claims <-
    case V4.verify vk parsed f i of
      Left err -> Left (V4PublicDecodingVerificationError err)
      Right x -> Right x
  first V4PublicDecodingCommonError (assertValid rs claims)
  Right ValidatedToken
    { vtToken = parsed
    , vtClaims = claims
    }
