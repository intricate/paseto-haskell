{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

module Test.Crypto.Paseto.Token.Gen
  ( genUnregisteredClaimKey
  , genClaim
  , genClaims
  , genPayload
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
import Crypto.Paseto.Token.Claim
  ( Audience (..)
  , Claim (..)
  , Expiration (..)
  , IssuedAt (..)
  , Issuer (..)
  , NotBefore (..)
  , Subject (..)
  , TokenIdentifier (..)
  , UnregisteredClaimKey
  , mkUnregisteredClaimKey
  )
import Crypto.Paseto.Token.Claims ( Claims, fromList )
import qualified Data.Aeson as Aeson
import Data.Time.Calendar.OrdinalDate ( Day, fromOrdinalDate )
import Data.Time.Clock ( DiffTime, UTCTime (..), secondsToDiffTime )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genUnregisteredClaimKey :: Gen UnregisteredClaimKey
genUnregisteredClaimKey =
  Gen.mapMaybe
    (mkUnregisteredClaimKey)
    (Gen.text (Range.constant 0 1024) Gen.unicodeAll)

genClaim :: Gen Claim
genClaim =
  Gen.choice
    [ IssuerClaim . Issuer <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll
    , SubjectClaim . Subject <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll
    , AudienceClaim . Audience <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll
    , ExpirationClaim . Expiration <$> genUTCTime
    , NotBeforeClaim . NotBefore <$> genUTCTime
    , IssuedAtClaim . IssuedAt <$> genUTCTime
    , TokenIdentifierClaim . TokenIdentifier <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll
    , CustomClaim <$> genUnregisteredClaimKey <*> genAesonString
    ]
  where
    genAesonString :: Gen Aeson.Value
    genAesonString = Aeson.String <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

    genDay :: Gen Day
    genDay =
      fromOrdinalDate
        <$> Gen.integral (Range.constant 0 3000)
        <*> Gen.int (Range.constant 1 365)

    genDiffTime :: Gen DiffTime
    genDiffTime = secondsToDiffTime <$> Gen.integral (Range.constant 0 86401)

    genUTCTime :: Gen UTCTime
    genUTCTime = UTCTime <$> genDay <*> genDiffTime

genClaims :: Gen Claims
genClaims = fromList <$> Gen.list (Range.constant 0 32) genClaim

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
