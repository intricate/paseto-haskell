{-# LANGUAGE FlexibleContexts #-}

-- | PASETO token parser.
module Crypto.Paseto.Token.Parser
  ( -- * Parser
    parseSomeToken

    -- ** Parsec parsers
  , pSomeToken
  , pVersion
  , pPurpose
  , pPayload
  , pFooter
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

-- | Parse a PASETO token from human-readable text according to the
-- [message format](https://github.com/paseto-standard/paseto-spec/tree/af79f25908227555404e7462ccdd8ce106049469/docs#paseto-message-format)
-- defined in the specification.
--
-- Note that this function does not perform any kind of token validation,
-- cryptographic or otherwise. It simply parses the token and ensures that it
-- is well-formed.
parseSomeToken :: Text -> Either ParseError SomeToken
parseSomeToken = parse pSomeToken ""

-- | Parse a PASETO token from its string representation.
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
  version <- pVersion
  period
  purpose <- pPurpose
  period
  payload <- pPayload <?> "payload"
  hasFooter <- isJust <$> optionMaybe period
  case hasFooter of
    False -> do
      eof
      pure $ mkToken version purpose payload Nothing
    True -> do
      f <- pFooter <?> "footer"
      eof
      pure $ mkToken version purpose payload (Just f)
  where
    mkToken :: Version -> Purpose -> Payload -> Maybe Footer -> SomeToken
    mkToken version purpose payload mbFooter =
      case (version, purpose) of
        (V3, Local) -> SomeTokenV3Local (TokenV3Local payload mbFooter)
        (V3, Public) -> SomeTokenV3Public (TokenV3Public payload mbFooter)
        (V4, Local) -> SomeTokenV4Local (TokenV4Local payload mbFooter)
        (V4, Public) -> SomeTokenV4Public (TokenV4Public payload mbFooter)

-- | Parse a 'Version' from its string representation.
pVersion :: Parser Version
pVersion =
  try (string "v3" $> V3)
    <|> (string "v4" $> V4)
    <?> "version"

-- | Parse a 'Purpose' from its string representation.
pPurpose :: Parser Purpose
pPurpose =
  try (string "local" $> Local)
    <|> (string "public" $> Public)
    <?> "purpose"

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

-- | Parse a valid @base64url@ character.
base64urlChar :: Stream s m Char => ParsecT s u m Char
base64urlChar = satisfy (\c -> isAsciiUpper c || isAsciiLower c || isDigit c || c == '-' || c == '_') <?> "base64url character"

-- | Period (\".\") parser.
period :: Parser ()
period = void $ char '.'
