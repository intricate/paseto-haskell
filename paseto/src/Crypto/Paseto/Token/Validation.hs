-- | PASETO token claim validation.
module Crypto.Paseto.Token.Validation
  ( -- * Errors
    ValidationError (..)

    -- * Rules
  , ValidationRule (..)
  , ClaimMustExist (..)
    -- ** Simple rules
  , forAudience
  , identifiedBy
  , issuedBy
  , notExpired
  , subject
  , validAt
  , customClaimEq
    -- * Recommended default rules
  , getDefaultValidationRules

    -- * Validation
  , validate
  , validateDefault
  ) where

import Crypto.Paseto.Token.Claim
  ( Audience (..)
  , ClaimKey (..)
  , Expiration (..)
  , IssuedAt (..)
  , Issuer (..)
  , NotBefore (..)
  , Subject (..)
  , TokenIdentifier (..)
  , UnregisteredClaimKey
  )
import Crypto.Paseto.Token.Claims
  ( Claims
  , lookupAudience
  , lookupCustom
  , lookupExpiration
  , lookupIssuedAt
  , lookupIssuer
  , lookupNotBefore
  , lookupSubject
  , lookupTokenIdentifier
  )
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import Data.Either ( lefts )
import qualified Data.List as L
import Data.List.NonEmpty ( NonEmpty )
import qualified Data.List.NonEmpty as NE
import Data.Text ( Text )
import qualified Data.Text.Encoding as TE
import Data.Time.Clock ( UTCTime, getCurrentTime )
import Prelude hiding ( exp, lookup )

-- | Validation error.
data ValidationError
  = -- | Expected claim does not exist.
    ValidationClaimNotFoundError
      -- | Claim key which could not be found.
      !ClaimKey
  | -- | Token claim is invalid.
    ValidationInvalidClaimError
      -- | Claim key.
      !ClaimKey
      -- | Expected claim value (rendered as 'Text').
      !Text
      -- | Actual claim value (rendered as 'Text').
      !Text
  | -- | Token is expired.
    ValidationExpirationError !Expiration
  | -- | Token's 'IssuedAt' time is in the future.
    ValidationIssuedAtError !IssuedAt
  | -- | Token is not yet valid as its 'NotBefore' time is in the future.
    ValidationNotBeforeError !NotBefore
  | -- | Custom validation error.
    ValidationCustomError !Text
  deriving stock (Show, Eq)

-- | Token claim validation rule.
newtype ValidationRule = ValidationRule
  { unValidationRule :: Claims -> Either ValidationError () }

-- | Whether a claim must exist.
newtype ClaimMustExist = ClaimMustExist Bool

-- | Build a simple validation rule which checks whether a value extracted
-- from the 'Claims' is equal to a given expected value.
mkEqValidationRule
  :: Eq a
  => (Claims -> Maybe a)
  -- ^ Extract a value from the claims (i.e. the actual value).
  -> ClaimKey
  -- ^ Claim key which corresponds to the extracted value (this is used in
  -- constructing errors).
  -> (a -> Text)
  -- ^ Render the expected value as 'Text' (this is used in constructing
  -- errors).
  -> a
  -- ^ Expected value.
  -> ValidationRule
mkEqValidationRule lookup claimKey render x = ValidationRule $ \cs ->
  case lookup cs of
    Just y
      | x == y -> Right ()
      | otherwise -> Left $ ValidationInvalidClaimError claimKey (render x) (render y)
    Nothing -> Left (ValidationClaimNotFoundError claimKey)

-- | Validate that a token is intended for a given audience.
forAudience :: Audience -> ValidationRule
forAudience = mkEqValidationRule lookupAudience AudienceClaimKey unAudience

-- | Validate a token's identifier.
identifiedBy :: TokenIdentifier -> ValidationRule
identifiedBy = mkEqValidationRule lookupTokenIdentifier TokenIdentifierClaimKey unTokenIdentifier

-- | Validate a token's issuer.
issuedBy :: Issuer -> ValidationRule
issuedBy = mkEqValidationRule lookupIssuer IssuerClaimKey unIssuer

-- | Validate that a token is not expired at the given time.
--
-- That is, if the 'Crypto.Paseto.Token.Claim.ExpirationClaim' is present,
-- check that it isn't in the past (relative to the given time).
notExpired :: UTCTime -> ValidationRule
notExpired x = ValidationRule $ \cs ->
  case lookupExpiration cs of
    Just exp@(Expiration y)
      | x <= y -> Right ()
      | otherwise -> Left (ValidationExpirationError exp)
    Nothing -> Right ()

-- | Validate the subject of a token.
subject :: Subject -> ValidationRule
subject = mkEqValidationRule lookupSubject SubjectClaimKey unSubject

-- | Validate that a token is valid at the given time.
--
-- This involves the following checks (relative to the given time):
--
-- * If the 'Crypto.Paseto.Token.Claim.ExpirationClaim' is present, check that
-- it isn't in the past.
--
-- * If the 'Crypto.Paseto.Token.Claim.IssuedAtClaim' is present, check that it
-- isn't in the future.
--
-- * If the 'Crypto.Paseto.Token.Claim.NotBeforeClaim' is present, check that
-- it isn't in the future.
validAt :: UTCTime -> ValidationRule
validAt x = ValidationRule $ \cs -> do
  unValidationRule (notExpired x) cs

  case lookupIssuedAt cs of
    Nothing -> Right ()
    Just iat@(IssuedAt y)
      | x >= y -> Right ()
      | otherwise -> Left (ValidationIssuedAtError iat)

  case lookupNotBefore cs of
    Nothing -> Right ()
    Just nbf@(NotBefore y)
      | x >= y -> Right ()
      | otherwise -> Left (ValidationNotBeforeError nbf)

-- | Validate that a custom claim is equal to the given value.
customClaimEq
  :: ClaimMustExist
  -- ^ Whether the custom claim must exist.
  -> UnregisteredClaimKey
  -- ^ Custom claim key to lookup.
  -> Aeson.Value
  -- ^ Custom claim value to validate (i.e. the expected value).
  -> ValidationRule
customClaimEq mustExist k expected = ValidationRule $ \cs ->
  case (mustExist, lookupCustom k cs) of
    (ClaimMustExist True, Nothing) -> Left (ValidationClaimNotFoundError $ CustomClaimKey k)
    (ClaimMustExist False, Nothing) -> Right ()
    (_, Just actual)
      | expected == actual -> Right ()
      | otherwise ->
          Left $
            ValidationInvalidClaimError
              (CustomClaimKey k)
              (TE.decodeUtf8 . BS.toStrict $ Aeson.encode expected)
              (TE.decodeUtf8 . BS.toStrict $ Aeson.encode actual)

-- | Get a list of
-- [recommended default validation rules](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/02-Implementation-Guide/05-API-UX.md#secure-defaults).
--
-- At the moment, the only default rule is checking 'validAt' for the current
-- system time ('getCurrentTime').
getDefaultValidationRules :: IO [ValidationRule]
getDefaultValidationRules = L.singleton . validAt <$> getCurrentTime

-- | Validate a list of rules against a collection of claims.
--
-- This function will run through all of the provided validation rules and
-- collect all of the errors encountered, if any. If there are no validation
-- errors, @Right ()@ is returned.
validate :: [ValidationRule] -> Claims -> Either (NonEmpty ValidationError) ()
validate rs cs =
  case NE.nonEmpty $ lefts (map v rs) of
    Just errs -> Left errs
    Nothing -> Right ()
  where
    v (ValidationRule f) = f cs

-- | Validate a collection of claims against the default validation rules
-- ('getDefaultValidationRules').
validateDefault :: Claims -> IO (Either (NonEmpty ValidationError) ())
validateDefault cs = flip validate cs <$> getDefaultValidationRules
