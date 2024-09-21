{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.Token.Validation
  ( tests
  ) where

import Crypto.Paseto.Token.Claim
  ( Claim (..), Expiration (..), IssuedAt (..), NotBefore (..) )
import qualified Crypto.Paseto.Token.Claims as Claims
import Crypto.Paseto.Token.Validation
  ( ValidationError (..)
  , forAudience
  , identifiedBy
  , issuedBy
  , notExpired
  , subject
  , validAt
  , validate
  )
import Data.Either ( isLeft )
import Data.Fixed ( Fixed (..), Pico, resolution )
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import Data.Time.Clock ( NominalDiffTime, addUTCTime, nominalDiffTimeToSeconds )
import Hedgehog
  ( MonadTest
  , Property
  , annotateShow
  , assert
  , checkParallel
  , discover
  , evalEither
  , forAll
  , forAllWith
  , property
  , withTests
  , (===)
  )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude hiding ( exp )
import Test.Crypto.Paseto.Token.Claim.Gen
  ( genAudience, genIssuer, genSubject, genTokenIdentifier )
import Test.Crypto.Paseto.Token.Validation.Gen ( genConstValidationRule )
import Test.Gen ( genNominalDiffTime, genUTCTime )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'validate' succeeds when all rules pass and fails when any rule
-- fails.
prop_validate :: Property
prop_validate = property $ do
  rules <- forAllWith renderRules $ Gen.list (Range.constant 1 128) genConstValidationRule
  let expectSuccess = and (map snd rules)
      validationResult = validate (map fst rules) Claims.empty
  if expectSuccess
    then evalEither validationResult
    else assert (isLeft validationResult)
  where
    renderRules xs = show $ map snd xs

prop_forAudience :: Property
prop_forAudience = property $ do
  aud <- forAll genAudience
  let claims = Claims.singleton (AudienceClaim aud)

  -- Expected success case
  evalEither (validate [forAudience aud] claims)

  -- Expected failure case
  wrong <- forAll $ Gen.filter (/= aud) genAudience
  assert $ isLeft (validate [forAudience wrong] claims)

prop_identifiedBy :: Property
prop_identifiedBy = property $ do
  jti <- forAll genTokenIdentifier
  let claims = Claims.singleton (TokenIdentifierClaim jti)

  -- Expected success case
  evalEither (validate [identifiedBy jti] claims)

  -- Expected failure case
  wrong <- forAll $ Gen.filter (/= jti) genTokenIdentifier
  assert $ isLeft (validate [identifiedBy wrong] claims)

prop_issuedBy :: Property
prop_issuedBy = property $ do
  iss <- forAll genIssuer
  let claims = Claims.singleton (IssuerClaim iss)

  -- Expected success case
  evalEither (validate [issuedBy iss] claims)

  -- Expected failure case
  wrong <- forAll $ Gen.filter (/= iss) genIssuer
  assert $ isLeft (validate [issuedBy wrong] claims)

prop_subject :: Property
prop_subject = property $ do
  sub <- forAll genSubject
  let claims = Claims.singleton (SubjectClaim sub)

  -- Expected success case
  evalEither (validate [subject sub] claims)

  -- Expected failure case
  wrong <- forAll $ Gen.filter (/= sub) genSubject
  assert $ isLeft (validate [subject wrong] claims)

prop_notExpired :: Property
prop_notExpired = withTests 5000 . property $ do
  time <- forAll genUTCTime
  expTimeDiff <- forAll $ genNominalDiffTime (Range.constant 0 100000)
  let expClaimTime = addUTCTime expTimeDiff time
      exp = Expiration expClaimTime
      claims = Claims.singleton (ExpirationClaim exp)

  -- Expected success case
  goodTime <- forAll $ do
    diff <- genNominalDiffTime (Range.constant 0 (nominalDiffTimeToSecondsI expTimeDiff))
    pure (addUTCTime diff time)
  evalEither (validate [notExpired goodTime] claims)

  -- Expected failure case
  badTime <- forAll $ do
    diff <- genNominalDiffTime (Range.constant 1 100000)
    pure (addUTCTime diff expClaimTime)
  assertErrors
    (NE.singleton $ ValidationExpirationError exp)
    (validate [notExpired badTime] claims)

prop_validAt :: Property
prop_validAt = withTests 5000 . property $ do
  timeBeforeIssue <- forAll genUTCTime

  iatTimeDiff <- forAll $ genNominalDiffTime (Range.constant 1 100000)
  let iatTime = addUTCTime iatTimeDiff timeBeforeIssue

  nbfTimeDiff <- forAll $ genNominalDiffTime (Range.constant 0 100000)
  let nbfTime = addUTCTime nbfTimeDiff iatTime

  expTimeDiff <- forAll $ genNominalDiffTime (Range.constant 1 100000)
  let expTime = addUTCTime expTimeDiff nbfTime

  let iat = IssuedAt iatTime
      nbf = NotBefore nbfTime
      exp = Expiration expTime
      claims =
        Claims.fromList
          [ IssuedAtClaim iat
          , NotBeforeClaim nbf
          , ExpirationClaim exp
          ]

  annotateShow claims

  -- Expected success case
  goodTime <- forAll $ do
    diff <- genNominalDiffTime (Range.constant 0 (nominalDiffTimeToSecondsI expTimeDiff))
    pure (addUTCTime diff nbfTime)
  evalEither (validate [validAt goodTime] claims)

  -- Expected failure case (claims not yet issued)
  badTimeBeforeIat <- forAll $ do
    diff <- genNominalDiffTime (Range.constant 0 ((nominalDiffTimeToSecondsI iatTimeDiff) - 1))
    pure (addUTCTime diff timeBeforeIssue)
  assertErrors
    (NE.singleton $ ValidationIssuedAtError iat)
    (validate [validAt badTimeBeforeIat] claims)

  -- Expected failure case (time is before `nbf`)
  badTimeBeforeNbf <- forAll $
    case nbfTimeDiff of
      0 -> do
        diff <- genNominalDiffTime (Range.constant 0 ((nominalDiffTimeToSecondsI iatTimeDiff) - 1))
        pure (addUTCTime diff timeBeforeIssue)
      _ -> do
        diff <- genNominalDiffTime (Range.constant 0 ((nominalDiffTimeToSecondsI nbfTimeDiff) - 1))
        pure (addUTCTime diff iatTime)
  assertErrors
    (NE.singleton $ ValidationNotBeforeError nbf)
    (validate [validAt badTimeBeforeNbf] claims)

  -- Expected failure case (expired claims)
  badTimeAfterExp <- forAll $ do
    diff <- genNominalDiffTime (Range.constant 1 100000)
    pure (addUTCTime diff expTime)
  assertErrors
    (NE.singleton $ ValidationExpirationError exp)
    (validate [validAt badTimeAfterExp] claims)

------------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------------

nominalDiffTimeToSecondsI :: NominalDiffTime -> Integer
nominalDiffTimeToSecondsI t = unFixed s `div` resolution s
  where
    s :: Pico
    s = nominalDiffTimeToSeconds t

    unFixed :: Fixed a -> Integer
    unFixed (MkFixed a) = a

assertErrors
  :: MonadTest m
  => NonEmpty ValidationError
  -> Either (NonEmpty ValidationError) ()
  -> m ()
assertErrors expectedErrs actualRes =
  Left expectedErrs === actualRes
