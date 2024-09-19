{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Token.Claims
  ( tests
  ) where

import Crypto.Paseto.Token.Claim ( Claim (..), claimKey )
import qualified Crypto.Paseto.Token.Claims as Claims
import Data.Foldable ( foldl' )
import qualified Data.List as L
import qualified Data.Set as Set
import Hedgehog
  ( Property
  , assert
  , checkParallel
  , discover
  , forAll
  , property
  , tripping
  , withTests
  , (===)
  )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude hiding ( exp )
import Test.Crypto.Paseto.Token.Claim.Gen
  ( genAesonString
  , genAudience
  , genClaim
  , genExpiration
  , genIssuedAt
  , genIssuer
  , genNotBefore
  , genSubject
  , genTokenIdentifier
  , genUnregisteredClaimKey
  )
import Test.Crypto.Paseto.Token.Claims.Gen ( genClaims, genNonEmptyClaims )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'Claims.toList' and 'Claims.fromList' round trip.
prop_roundTrip_toFromList :: Property
prop_roundTrip_toFromList = property $ do
  cs <- forAll genClaims
  tripping cs Claims.toList (Just . Claims.fromList)

-- | Test that the size of an empty collection of claims is zero.
prop_emptySizeIsZero :: Property
prop_emptySizeIsZero = withTests 1 . property $ do
  Claims.size (Claims.empty) === 0
  Claims.size (Claims.fromList []) === 0

-- | Test that the size of a 'Claims' value constructed with 'Claims.singleton'
-- is one.
prop_singletonSizeIsOne :: Property
prop_singletonSizeIsOne = property $ do
  c <- forAll genClaim
  Claims.size (Claims.singleton c) === 1

-- | Test that 'Claims.size' accurately reflects the size of the collection.
prop_size :: Property
prop_size = property $ do
  claimsList <- forAll $ Gen.list (Range.constant 0 32) genClaim
  let expectedSize = countUniqueClaims claimsList
      actualSize = Claims.size (Claims.fromList claimsList)
  expectedSize === actualSize
  where
    countUniqueClaims :: [Claim] -> Int
    countUniqueClaims = Set.size . foldl' (\acc c -> Set.insert (claimKey c) acc) Set.empty

-- | Test that 'Claims.null' appropriately reflects whether the collection is
-- empty.
prop_null :: Property
prop_null = property $ do
  claims <- forAll genClaims
  case Claims.size claims of
    0 -> assert (Claims.null claims)
    _ -> assert (not $ Claims.null claims)

-- | Test that 'Claims.delete' deletes a claim from the collection.
prop_delete :: Property
prop_delete = property $ do
  claims <- forAll genNonEmptyClaims
  let claimsList = Claims.toList claims
  randomClaim <- forAll $ Gen.element claimsList
  Claims.toList (Claims.delete (claimKey randomClaim) claims) === L.delete randomClaim claimsList

-- | Test that 'Claims.insert' inserts a claim into the collection.
prop_insert :: Property
prop_insert = property $ do
  claims <- forAll genClaims
  claim <- forAll genClaim
  assert (L.elem claim $ Claims.toList (Claims.insert claim claims))

prop_lookupIssuer :: Property
prop_lookupIssuer = property $ do
  iss <- forAll genIssuer
  claims <- forAll $ Claims.insert (IssuerClaim iss) <$> genClaims
  Just iss === Claims.lookupIssuer claims

prop_lookupSubject :: Property
prop_lookupSubject = property $ do
  sub <- forAll genSubject
  claims <- forAll $ Claims.insert (SubjectClaim sub) <$> genClaims
  Just sub === Claims.lookupSubject claims

prop_lookupAudience :: Property
prop_lookupAudience = property $ do
  aud <- forAll genAudience
  claims <- forAll $ Claims.insert (AudienceClaim aud) <$> genClaims
  Just aud === Claims.lookupAudience claims

prop_lookupExpiration :: Property
prop_lookupExpiration = property $ do
  exp <- forAll genExpiration
  claims <- forAll $ Claims.insert (ExpirationClaim exp) <$> genClaims
  Just exp === Claims.lookupExpiration claims

prop_lookupNotBefore :: Property
prop_lookupNotBefore = property $ do
  nbf <- forAll genNotBefore
  claims <- forAll $ Claims.insert (NotBeforeClaim nbf) <$> genClaims
  Just nbf === Claims.lookupNotBefore claims

prop_lookupIssuedAt :: Property
prop_lookupIssuedAt = property $ do
  iat <- forAll genIssuedAt
  claims <- forAll $ Claims.insert (IssuedAtClaim iat) <$> genClaims
  Just iat === Claims.lookupIssuedAt claims

prop_lookupTokenIdentifier :: Property
prop_lookupTokenIdentifier = property $ do
  jti <- forAll genTokenIdentifier
  claims <- forAll $ Claims.insert (TokenIdentifierClaim jti) <$> genClaims
  Just jti === Claims.lookupTokenIdentifier claims

prop_lookupCustom :: Property
prop_lookupCustom = property $ do
  k <- forAll genUnregisteredClaimKey
  v <- forAll genAesonString
  claims <- forAll $ Claims.insert (CustomClaim k v) <$> genClaims
  Just v === Claims.lookupCustom k claims
