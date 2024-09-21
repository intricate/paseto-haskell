{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

module Test.Crypto.Paseto.Token.Claim.Gen
  ( genUnregisteredClaimKey
  , genCustomClaimKey
  , genClaimKey
  , genIssuer
  , genSubject
  , genAudience
  , genExpiration
  , genNotBefore
  , genIssuedAt
  , genTokenIdentifier
  , genClaim
  , genAesonString
  , genUTCTime
  ) where

import Crypto.Paseto.Token.Claim
  ( Audience (..)
  , Claim (..)
  , ClaimKey (..)
  , Expiration (..)
  , IssuedAt (..)
  , Issuer (..)
  , NotBefore (..)
  , Subject (..)
  , TokenIdentifier (..)
  , UnregisteredClaimKey
  , mkUnregisteredClaimKey
  , parseClaimKey
  , registeredClaimKeys
  )
import qualified Data.Set as Set
import Data.Text ( Text )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Gen ( genAesonString, genUTCTime )

genUnregisteredClaimKey :: Gen UnregisteredClaimKey
genUnregisteredClaimKey =
  Gen.mapMaybe
    (mkUnregisteredClaimKey)
    (Gen.text (Range.constant 0 1024) Gen.unicodeAll)

genCustomClaimKey :: Gen ClaimKey
genCustomClaimKey = Gen.filter isNotRegistered (parseClaimKey <$> genText)
  where
    isNotRegistered :: ClaimKey -> Bool
    isNotRegistered k = Set.notMember k registeredClaimKeys

    genText :: Gen Text
    genText = Gen.text (Range.constant 0 1024) Gen.unicodeAll

genClaimKey :: Gen ClaimKey
genClaimKey =
  Gen.choice (genCustomClaimKey : map pure (Set.toList registeredClaimKeys))

genIssuer :: Gen Issuer
genIssuer = Issuer <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

genSubject :: Gen Subject
genSubject = Subject <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

genAudience :: Gen Audience
genAudience = Audience <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

genExpiration :: Gen Expiration
genExpiration = Expiration <$> genUTCTime

genNotBefore :: Gen NotBefore
genNotBefore = NotBefore <$> genUTCTime

genIssuedAt :: Gen IssuedAt
genIssuedAt = IssuedAt <$> genUTCTime

genTokenIdentifier :: Gen TokenIdentifier
genTokenIdentifier = TokenIdentifier <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

genClaim :: Gen Claim
genClaim =
  Gen.choice
    [ IssuerClaim <$> genIssuer
    , SubjectClaim <$> genSubject
    , AudienceClaim <$> genAudience
    , ExpirationClaim <$> genExpiration
    , NotBeforeClaim <$> genNotBefore
    , IssuedAtClaim <$> genIssuedAt
    , TokenIdentifierClaim <$> genTokenIdentifier
    , CustomClaim <$> genUnregisteredClaimKey <*> genAesonString
    ]
