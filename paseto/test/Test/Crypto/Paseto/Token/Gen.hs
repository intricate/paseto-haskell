{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

module Test.Crypto.Paseto.Token.Gen
  ( genPayload
  , genFooter
  , genImplicitAssertion
  , genTokenV3Local
  , genTokenV3Public
  , genTokenV4Local
  , genTokenV4Public
  , genSomeToken
  ) where

import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Crypto.Paseto.Token
  ( Footer (..)
  , ImplicitAssertion (..)
  , Payload (..)
  , SomeToken (..)
  , Token (..)
  )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genPayload :: Gen Payload
genPayload = Payload <$> Gen.bytes (Range.constant 1 1024)

genFooter :: Gen Footer
genFooter = Footer <$> Gen.bytes (Range.constant 1 1024)

genImplicitAssertion :: Gen ImplicitAssertion
genImplicitAssertion = ImplicitAssertion <$> Gen.bytes (Range.constant 1 1024)

-- | Generate a cryptographically-invalid PASETO v3 local token.
genTokenV3Local :: Gen (Token V3 Local)
genTokenV3Local =
  TokenV3Local
    <$> genPayload
    <*> Gen.maybe genFooter

-- | Generate a cryptographically-invalid PASETO v3 public token.
genTokenV3Public :: Gen (Token V3 Public)
genTokenV3Public =
  TokenV3Public
    <$> genPayload
    <*> Gen.maybe genFooter

-- | Generate a cryptographically-invalid PASETO v4 local token.
genTokenV4Local :: Gen (Token V4 Local)
genTokenV4Local =
  TokenV4Local
    <$> genPayload
    <*> Gen.maybe genFooter

-- | Generate a cryptographically-invalid PASETO v4 public token.
genTokenV4Public :: Gen (Token V4 Public)
genTokenV4Public =
  TokenV4Public
    <$> genPayload
    <*> Gen.maybe genFooter

-- | Generate a cryptographically-invalid PASETO token.
genSomeToken :: Gen SomeToken
genSomeToken =
  Gen.choice
    [ SomeTokenV3Local <$> genTokenV3Local
    , SomeTokenV3Public <$> genTokenV3Public
    , SomeTokenV4Local <$> genTokenV4Local
    , SomeTokenV4Public <$> genTokenV4Public
    ]
