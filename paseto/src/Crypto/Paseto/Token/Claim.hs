{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}

-- | PASETO token claim.
module Crypto.Paseto.Token.Claim
  ( -- * Claim value types
    Issuer (..)
  , Subject (..)
  , Audience (..)
  , Expiration (..)
  , renderExpiration
  , NotBefore (..)
  , renderNotBefore
  , IssuedAt (..)
  , renderIssuedAt
  , TokenIdentifier (..)

    -- * Claim key
  , ClaimKey
      ( IssuerClaimKey
      , SubjectClaimKey
      , AudienceClaimKey
      , ExpirationClaimKey
      , NotBeforeClaimKey
      , IssuedAtClaimKey
      , TokenIdentifierClaimKey
      , CustomClaimKey
      )
  , renderClaimKey
  , parseClaimKey
  , registeredClaimKeys
    -- ** Unregistered claim key
  , UnregisteredClaimKey
  , mkUnregisteredClaimKey
  , renderUnregisteredClaimKey

    -- * Claim
  , Claim (..)
  , claimKey
  , claimToPair
  , claimFromJson
  ) where

import Data.Aeson ( FromJSON (..), ToJSON (..) )
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Aeson
import qualified Data.Aeson.Types as Aeson
import Data.Set ( Set )
import qualified Data.Set as Set
import Data.Text ( Text )
import qualified Data.Text as T
import Data.Time.Clock ( UTCTime )
import Data.Time.Format.ISO8601 ( iso8601Show )
import Prelude

------------------------------------------------------------------------------
-- Claim value types
------------------------------------------------------------------------------

-- | Issuer of a token.
newtype Issuer = Issuer
  { unIssuer :: Text }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

-- | Subject of a token.
newtype Subject = Subject
  { unSubject :: Text }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

-- | Recipient for which a token is intended.
newtype Audience = Audience
  { unAudience :: Text }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

-- | Time after which a token expires.
newtype Expiration = Expiration
  { unExpiration :: UTCTime }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

-- | Render an 'Expiration' as 'Text'.
renderExpiration :: Expiration -> Text
renderExpiration (Expiration t) = T.pack (iso8601Show t)

-- | Time from which a token should be considered valid.
newtype NotBefore = NotBefore
  { unNotBefore :: UTCTime }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

-- | Render a 'NotBefore' as 'Text'.
renderNotBefore :: NotBefore -> Text
renderNotBefore (NotBefore t) = T.pack (iso8601Show t)

-- | Time at which a token was issued.
newtype IssuedAt = IssuedAt
  { unIssuedAt :: UTCTime }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

-- | Render an 'IssuedAt' as 'Text'.
renderIssuedAt :: IssuedAt -> Text
renderIssuedAt (IssuedAt t) = T.pack (iso8601Show t)

-- | Token identifier.
newtype TokenIdentifier = TokenIdentifier
  { unTokenIdentifier :: Text }
  deriving newtype (Show, Eq, ToJSON, FromJSON)

------------------------------------------------------------------------------
-- Claim key
------------------------------------------------------------------------------

-- | Token claim key.
newtype ClaimKey = MkClaimKey Text
  deriving newtype (Show, Eq)

instance Ord ClaimKey where
  x `compare` y = renderClaimKey x `compare` renderClaimKey y

-- | Render a 'ClaimKey' as 'Text'.
renderClaimKey :: ClaimKey -> Text
renderClaimKey (MkClaimKey t) = t

-- | Parse a 'ClaimKey' from 'Text'.
parseClaimKey :: Text -> ClaimKey
parseClaimKey = MkClaimKey

pattern IssuerClaimKey :: ClaimKey
pattern IssuerClaimKey = MkClaimKey "iss"

pattern SubjectClaimKey :: ClaimKey
pattern SubjectClaimKey = MkClaimKey "sub"

pattern AudienceClaimKey :: ClaimKey
pattern AudienceClaimKey = MkClaimKey "aud"

pattern ExpirationClaimKey :: ClaimKey
pattern ExpirationClaimKey = MkClaimKey "exp"

pattern NotBeforeClaimKey :: ClaimKey
pattern NotBeforeClaimKey = MkClaimKey "nbf"

pattern IssuedAtClaimKey :: ClaimKey
pattern IssuedAtClaimKey = MkClaimKey "iat"

pattern TokenIdentifierClaimKey :: ClaimKey
pattern TokenIdentifierClaimKey = MkClaimKey "jti"

pattern CustomClaimKey :: UnregisteredClaimKey -> ClaimKey
pattern CustomClaimKey k <- (mkUnregisteredClaimKey . renderClaimKey -> Just k) where
  CustomClaimKey (UnregisteredClaimKey k) = MkClaimKey k

{-# COMPLETE IssuerClaimKey, SubjectClaimKey, AudienceClaimKey, ExpirationClaimKey, NotBeforeClaimKey, IssuedAtClaimKey, TokenIdentifierClaimKey, CustomClaimKey #-}

-- | Registered claims as defined by the
-- [PASETO specification](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/02-Implementation-Guide/04-Claims.md#registered-claims).
registeredClaimKeys :: Set ClaimKey
registeredClaimKeys =
  Set.fromList
    [ IssuerClaimKey
    , SubjectClaimKey
    , AudienceClaimKey
    , ExpirationClaimKey
    , NotBeforeClaimKey
    , IssuedAtClaimKey
    , TokenIdentifierClaimKey
    ]

------------------------------------------------------------------------------
-- Unregistered claim key
------------------------------------------------------------------------------

-- | Unregistered claim key.
newtype UnregisteredClaimKey = UnregisteredClaimKey Text
  deriving newtype (Show, Eq)

-- | Construct an unregistered claim key.
--
-- If the provided @Text@ key matches that of a registered claim
-- ('registeredClaimKeys'), this function will return 'Nothing'.
mkUnregisteredClaimKey :: Text -> Maybe UnregisteredClaimKey
mkUnregisteredClaimKey t
  | Set.member (MkClaimKey t) registeredClaimKeys = Nothing
  | otherwise = Just (UnregisteredClaimKey t)

-- | Render an 'UnregisteredClaimKey' as 'Text'.
renderUnregisteredClaimKey :: UnregisteredClaimKey -> Text
renderUnregisteredClaimKey (UnregisteredClaimKey t) = t

------------------------------------------------------------------------------
-- Claim
------------------------------------------------------------------------------

-- | Token claim.
data Claim
  = IssuerClaim !Issuer
  | SubjectClaim !Subject
  | AudienceClaim !Audience
  | ExpirationClaim !Expiration
  | NotBeforeClaim !NotBefore
  | IssuedAtClaim !IssuedAt
  | TokenIdentifierClaim !TokenIdentifier
  | CustomClaim
      -- | Claim key.
      !UnregisteredClaimKey
      -- | Claim value.
      !Aeson.Value
  deriving stock (Show, Eq)

-- | Get the JSON object key which corresponds to a 'Claim'.
claimKey :: Claim -> ClaimKey
claimKey c =
  case c of
    IssuerClaim _ -> IssuerClaimKey
    SubjectClaim _ -> SubjectClaimKey
    AudienceClaim _ -> AudienceClaimKey
    ExpirationClaim _ -> ExpirationClaimKey
    NotBeforeClaim _ -> NotBeforeClaimKey
    IssuedAtClaim _ -> IssuedAtClaimKey
    TokenIdentifierClaim _ -> TokenIdentifierClaimKey
    CustomClaim k _ -> CustomClaimKey k

claimToPair :: Claim -> Aeson.Pair
claimToPair c = (,) (Aeson.fromText . renderClaimKey $ claimKey c) $
  case c of
    IssuerClaim v -> toJSON v
    SubjectClaim v -> toJSON v
    AudienceClaim v -> toJSON v
    ExpirationClaim v -> toJSON v
    NotBeforeClaim v -> toJSON v
    IssuedAtClaim v -> toJSON v
    TokenIdentifierClaim v -> toJSON v
    CustomClaim _ v -> v

claimFromJson :: Aeson.Key -> Aeson.Value -> Aeson.Parser Claim
claimFromJson k v =
  case parseClaimKey (Aeson.toText k) of
    IssuerClaimKey -> IssuerClaim <$> parseJSON v
    SubjectClaimKey -> SubjectClaim <$> parseJSON v
    AudienceClaimKey -> AudienceClaim <$> parseJSON v
    ExpirationClaimKey -> ExpirationClaim <$> parseJSON v
    NotBeforeClaimKey -> NotBeforeClaim <$> parseJSON v
    IssuedAtClaimKey -> IssuedAtClaim <$> parseJSON v
    TokenIdentifierClaimKey -> TokenIdentifierClaim <$> parseJSON v
    CustomClaimKey x -> CustomClaim x <$> parseJSON v
