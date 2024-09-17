-- | Collection of PASETO token claims.
module Crypto.Paseto.Token.Claims
  ( -- * Claims type
    Claims

    -- * Construction
  , empty
  , singleton
    -- ** Insertion
  , insert
    -- ** Deletion
  , delete

    -- * Query
  , lookupIssuer
  , lookupSubject
  , lookupAudience
  , lookupExpiration
  , lookupNotBefore
  , lookupIssuedAt
  , lookupTokenIdentifier
  , lookupCustom
  , null
  , size

    -- * Conversion
  , toList
  , fromList
  ) where

import Control.Monad ( foldM )
import Crypto.Paseto.Token.Claim
  ( Audience
  , Claim (..)
  , ClaimKey (..)
  , Expiration
  , IssuedAt
  , Issuer
  , NotBefore
  , Subject
  , TokenIdentifier
  , UnregisteredClaimKey
  , claimFromJson
  , claimKey
  , claimToPair
  , parseClaimKey
  )
import Data.Aeson ( FromJSON (..), ToJSON (..) )
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Aeson
import qualified Data.Aeson.KeyMap as Aeson
import Data.Map.Strict ( Map )
import qualified Data.Map.Strict as Map
import Prelude hiding ( lookup, null )

------------------------------------------------------------------------------
-- Claims type
------------------------------------------------------------------------------

-- | Collection of 'Claim's.
newtype Claims = Claims
  { unClaims :: Map ClaimKey Claim }
  deriving newtype (Show, Eq)

instance ToJSON Claims where
  toJSON = Aeson.object . map (claimToPair . snd) . Map.toList . unClaims

instance FromJSON Claims where
  parseJSON = Aeson.withObject "Claims" $ \o -> do
    let kvs = Aeson.toList o
    foldM parseAndAccumClaims empty kvs
    where
      parseAndAccumClaims (Claims acc) (k, v) = do
        c <- claimFromJson k v
        pure . Claims $ Map.insert (parseClaimKey $ Aeson.toText k) c acc

------------------------------------------------------------------------------
-- Construction
------------------------------------------------------------------------------

-- | Empty collection of claims.
empty :: Claims
empty = Claims Map.empty

-- | Construct a collection of claims with a single element.
singleton :: Claim -> Claims
singleton c = Claims $ Map.singleton (claimKey c) c

-- | Insert a 'Claim' into a collection of 'Claims'.
--
-- Note that if a claim with the same key is already present, it is replaced
-- with the provided claim.
insert :: Claim -> Claims -> Claims
insert c = Claims . Map.insert (claimKey c) c . unClaims

-- | Delete a claim from the collection.
delete :: ClaimKey -> Claims -> Claims
delete k = Claims . Map.delete k . unClaims

------------------------------------------------------------------------------
-- Query
------------------------------------------------------------------------------

-- | Lookup a 'Claim' by its key.
--
-- Note that this function is not intended to be exported as it can be a bit
-- error prone.
lookup :: ClaimKey -> Claims -> Maybe Claim
lookup k = Map.lookup k . unClaims

-- | Lookup the issuer claim.
lookupIssuer :: Claims -> Maybe Issuer
lookupIssuer cs =
  case lookup IssuerClaimKey cs of
    Nothing -> Nothing
    Just (IssuerClaim i) -> Just i
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup the subject claim.
lookupSubject :: Claims -> Maybe Subject
lookupSubject cs =
  case lookup SubjectClaimKey cs of
    Nothing -> Nothing
    Just (SubjectClaim s) -> Just s
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup the audience claim.
lookupAudience :: Claims -> Maybe Audience
lookupAudience cs =
  case lookup AudienceClaimKey cs of
    Nothing -> Nothing
    Just (AudienceClaim a) -> Just a
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup the expiration claim.
lookupExpiration :: Claims -> Maybe Expiration
lookupExpiration cs =
  case lookup ExpirationClaimKey cs of
    Nothing -> Nothing
    Just (ExpirationClaim e) -> Just e
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup the \"not before\" claim.
lookupNotBefore :: Claims -> Maybe NotBefore
lookupNotBefore cs =
  case lookup NotBeforeClaimKey cs of
    Nothing -> Nothing
    Just (NotBeforeClaim nb) -> Just nb
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup the \"issued at\" claim.
lookupIssuedAt :: Claims -> Maybe IssuedAt
lookupIssuedAt cs =
  case lookup IssuedAtClaimKey cs of
    Nothing -> Nothing
    Just (IssuedAtClaim ia) -> Just ia
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup the token identifier claim.
lookupTokenIdentifier :: Claims -> Maybe TokenIdentifier
lookupTokenIdentifier cs =
  case lookup TokenIdentifierClaimKey cs of
    Nothing -> Nothing
    Just (TokenIdentifierClaim ti) -> Just ti
    Just _ -> error "impossible: invalid claim for key"

-- | Lookup a custom unregistered claim.
lookupCustom :: UnregisteredClaimKey -> Claims -> Maybe Aeson.Value
lookupCustom k cs =
  case lookup (CustomClaimKey k) cs of
    Nothing -> Nothing
    Just (CustomClaim _ v) -> Just v
    Just _ -> error "impossible: invalid claim for key"

-- | Whether a collection of claims is empty.
null :: Claims -> Bool
null = Map.null . unClaims

-- | Size of a collection of claims.
size :: Claims -> Int
size = Map.size . unClaims

------------------------------------------------------------------------------
-- Conversion
------------------------------------------------------------------------------

-- | Convert a collection of 'Claims' to a list of 'Claim's.
toList :: Claims -> [Claim]
toList = Map.elems . unClaims

-- | Convert a list of 'Claim's to a collection of 'Claims'.
--
-- Note that if the provided list contains more than one value for the same
-- claim, the last value for that claim is retained.
fromList :: [Claim] -> Claims
fromList = Claims . Map.fromList . map (\c -> (claimKey c, c))
