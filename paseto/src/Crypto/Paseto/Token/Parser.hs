{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}

-- | Parsers for PASETO tokens according to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that the parsers exported from this module /do not/ perform any kind
-- of token validation, cryptographic or otherwise. These parsers simply
-- ensure that the input /looks like/ a well-formed token.
module Crypto.Paseto.Token.Parser
  ( -- * Token parsers
    parseTokenV3Local
  , parseTokenV3Public
  , parseTokenV4Local
  , parseTokenV4Public
  , parseSomeToken

    -- ** Parsec parsers
  , pVersion
  , pVersionV3
  , pVersionV4
  , pPurpose
  , pPurposeLocal
  , pPurposePublic
  , pPayload
  , pFooter
  , pPayloadAndFooter
  , pTokenParts
  , pTokenV3Local
  , pTokenV3Public
  , pTokenV4Local
  , pTokenV4Public
  , pSomeToken
  ) where

import Control.Applicative ( some, (<|>) )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Crypto.Paseto.Token
  ( Footer (..), Payload (..), SomeToken (..), Token (..) )
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Char8 as B8
import Data.Char ( isAsciiLower, isAsciiUpper, isDigit )
import Data.Functor ( void, ($>) )
import Data.Maybe ( isJust )
import Data.Text ( Text )
import Prelude
import Text.Parsec
  ( ParseError
  , ParsecT
  , Stream
  , char
  , eof
  , optionMaybe
  , parse
  , satisfy
  , string
  , try
  , (<?>)
  )
import Text.Parsec.Text ( Parser )

-- | Parse a version 3 local PASETO token from human-readable text according
-- to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that this function does not perform any kind of token validation,
-- cryptographic or otherwise. It simply parses the token and ensures that it
-- is well-formed.
parseTokenV3Local :: Text -> Either ParseError (Token V3 Local)
parseTokenV3Local = parse pTokenV3Local ""

-- | Parse a version 3 public PASETO token from human-readable text according
-- to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that this function does not perform any kind of token validation,
-- cryptographic or otherwise. It simply parses the token and ensures that it
-- is well-formed.
parseTokenV3Public :: Text -> Either ParseError (Token V3 Public)
parseTokenV3Public = parse pTokenV3Public ""

-- | Parse a version 4 local PASETO token from human-readable text according
-- to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that this function does not perform any kind of token validation,
-- cryptographic or otherwise. It simply parses the token and ensures that it
-- is well-formed.
parseTokenV4Local :: Text -> Either ParseError (Token V4 Local)
parseTokenV4Local = parse pTokenV4Local ""

-- | Parse a version 4 public PASETO token from human-readable text according
-- to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that this function does not perform any kind of token validation,
-- cryptographic or otherwise. It simply parses the token and ensures that it
-- is well-formed.
parseTokenV4Public :: Text -> Either ParseError (Token V4 Public)
parseTokenV4Public = parse pTokenV4Public ""

-- | Parse some kind of PASETO token from human-readable text according to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that this function does not perform any kind of token validation,
-- cryptographic or otherwise. It simply parses the token and ensures that it
-- is well-formed.
parseSomeToken :: Text -> Either ParseError SomeToken
parseSomeToken = parse pSomeToken ""

------------------------------------------------------------------------------
-- Parsec parsers
------------------------------------------------------------------------------

-- | Parse a valid @base64url@ character.
base64urlChar :: Stream s m Char => ParsecT s u m Char
base64urlChar = satisfy (\c -> isAsciiUpper c || isAsciiLower c || isDigit c || c == '-' || c == '_') <?> "base64url character"

-- | Period (\".\") parser.
period :: Parser ()
period = void $ char '.'

-- | Parse a 'Version' from its string representation.
pVersion :: Parser Version
pVersion =
  try pVersionV3
    <|> pVersionV4
    <?> "version"

-- | Parse the 'Version' string @v3@.
pVersionV3 :: Parser Version
pVersionV3 = string "v3" $> V3

-- | Parse the 'Version' string @v4@.
pVersionV4 :: Parser Version
pVersionV4 = string "v4" $> V4

-- | Parse a 'Purpose' from its string representation.
pPurpose :: Parser Purpose
pPurpose =
  try pPurposeLocal
    <|> pPurposePublic
    <?> "purpose"

-- | Parse the 'Purpose' string @local@.
pPurposeLocal :: Parser Purpose
pPurposeLocal = string "local" $> Local

-- | Parse the 'Purpose' string @public@.
pPurposePublic :: Parser Purpose
pPurposePublic = string "public" $> Public

-- | Parse a 'Payload' from its string representation.
pPayload :: Parser Payload
pPayload = do
  payloadB64 <- B8.pack <$> some base64urlChar
  case B64URL.decodeUnpadded payloadB64 of
    Left err -> fail err
    Right x -> pure (Payload x)

-- | Parse a 'Footer' from its string representation.
pFooter :: Parser Footer
pFooter = do
  footerB64 <- B8.pack <$> some base64urlChar
  case B64URL.decodeUnpadded footerB64 of
    Left err -> fail err
    Right x -> pure (Footer x)

-- | Parse a 'Payload' along with an optional 'Footer'.
pPayloadAndFooter :: Parser (Payload, Maybe Footer)
pPayloadAndFooter = do
  payload <- pPayload <?> "payload"
  hasFooter <- isJust <$> optionMaybe period
  case hasFooter of
    False -> do
      eof
      pure (payload, Nothing)
    True -> do
      footer <- pFooter <?> "footer"
      eof
      pure (payload, Just footer)

-- | Parse the parts of a PASETO token: version, purpose, payload, and an
-- optional footer.
pTokenParts
  :: Parser Version
  -- ^ Parser for the 'Version' part of a token.
  -> Parser Purpose
  -- ^ Parser for the 'Purpose' part of a token.
  -> Parser (Version, Purpose, Payload, Maybe Footer)
pTokenParts pV pP = do
  version <- pV
  period
  purpose <- pP
  period
  (payload, mbFooter) <- pPayloadAndFooter
  pure (version, purpose, payload, mbFooter)

-- | Parse a version 3 local PASETO token from its string representation.
--
-- Accepted token format:
--
-- * Without the optional footer: @v3.local.${payload}@
--
-- * With the optional footer: @v3.local.${payload}.${footer}@
--
-- Both the @payload@ and optional @footer@ are @base64url@-encoded values
-- (unpadded).
pTokenV3Local :: Parser (Token V3 Local)
pTokenV3Local = do
  (_, _, payload, mbFooter) <- pTokenParts pVersionV3 pPurposeLocal
  pure (TokenV3Local payload mbFooter)

-- | Parse a version 3 public PASETO token from its string representation.
--
-- Accepted token format:
--
-- * Without the optional footer: @v3.public.${payload}@
--
-- * With the optional footer: @v3.public.${payload}.${footer}@
--
-- Both the @payload@ and optional @footer@ are @base64url@-encoded values
-- (unpadded).
pTokenV3Public :: Parser (Token V3 Public)
pTokenV3Public = do
  (_, _, payload, mbFooter) <- pTokenParts pVersionV3 pPurposePublic
  pure (TokenV3Public payload mbFooter)

-- | Parse a version 4 local PASETO token from its string representation.
--
-- Accepted token format:
--
-- * Without the optional footer: @v4.local.${payload}@
--
-- * With the optional footer: @v4.local.${payload}.${footer}@
--
-- Both the @payload@ and optional @footer@ are @base64url@-encoded values
-- (unpadded).
pTokenV4Local :: Parser (Token V4 Local)
pTokenV4Local = do
  (_, _, payload, mbFooter) <- pTokenParts pVersionV4 pPurposeLocal
  pure (TokenV4Local payload mbFooter)

-- | Parse a version 4 public PASETO token from its string representation.
--
-- Accepted token format:
--
-- * Without the optional footer: @v4.public.${payload}@
--
-- * With the optional footer: @v4.public.${payload}.${footer}@
--
-- Both the @payload@ and optional @footer@ are @base64url@-encoded values
-- (unpadded).
pTokenV4Public :: Parser (Token V4 Public)
pTokenV4Public = do
  (_, _, payload, mbFooter) <- pTokenParts pVersionV4 pPurposePublic
  pure (TokenV4Public payload mbFooter)

-- | Parse some kind of PASETO token from its string representation.
--
-- PASETO token format:
--
-- * Without the optional footer: @version.purpose.payload@
--
-- * With the optional footer: @version.purpose.payload.footer@
--
-- Acceptable values for @version@ are @v3@ and @v4@. @v1@ and @v2@ are
-- deprecated, so they're not supported.
--
-- Acceptable values for @purpose@ are @local@ and @public@.
--
-- Both the @payload@ and optional @footer@ are @base64url@-encoded values
-- (unpadded).
pSomeToken :: Parser SomeToken
pSomeToken = do
  (version, purpose, payload, mbFooter) <- pTokenParts pVersion pPurpose
  pure (mkToken version purpose payload mbFooter)
  where
    mkToken :: Version -> Purpose -> Payload -> Maybe Footer -> SomeToken
    mkToken version purpose payload mbFooter =
      case (version, purpose) of
        (V3, Local) -> SomeTokenV3Local (TokenV3Local payload mbFooter)
        (V3, Public) -> SomeTokenV3Public (TokenV3Public payload mbFooter)
        (V4, Local) -> SomeTokenV4Local (TokenV4Local payload mbFooter)
        (V4, Public) -> SomeTokenV4Public (TokenV4Public payload mbFooter)
