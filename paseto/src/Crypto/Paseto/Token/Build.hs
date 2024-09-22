{-# LANGUAGE DataKinds #-}

module Crypto.Paseto.Token.Build
  ( BuildTokenParams (..)
  , getDefaultBuildTokenParams
  , V3LocalBuildError (..)
  , renderV3LocalBuildError
  , buildTokenV3Local
  , V3PublicBuildError (..)
  , renderV3PublicBuildError
  , buildTokenV3Public
  , buildTokenV4Local
  , buildTokenV4Public
  ) where

import Control.Monad.Except ( ExceptT )
import Control.Monad.Trans.Except.Extra ( firstExceptT )
import Crypto.Paseto.Keys ( SigningKey (..), SymmetricKey (..) )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import qualified Crypto.Paseto.Protocol.V3 as V3
import qualified Crypto.Paseto.Protocol.V4 as V4
import Crypto.Paseto.Token ( Footer, ImplicitAssertion, Token (..) )
import Crypto.Paseto.Token.Claim
  ( Claim (..), Expiration (..), IssuedAt (..), NotBefore (..) )
import Crypto.Paseto.Token.Claims ( Claims )
import qualified Crypto.Paseto.Token.Claims as Claims
import Data.Text ( Text )
import Data.Time.Clock ( addUTCTime, getCurrentTime, secondsToNominalDiffTime )
import Prelude hiding ( exp )

-- | Parameters for building a PASETO token.
data BuildTokenParams = BuildTokenParams
  { btpClaims :: !Claims
  , btpFooter :: !(Maybe Footer)
  , btpImplicitAssertion :: !(Maybe ImplicitAssertion)
  } deriving stock (Show, Eq)

-- | Get parameters for building a PASETO token which includes the
-- [recommended default claims](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/02-Implementation-Guide/05-API-UX.md#secure-defaults).
--
-- This includes the following default claims:
--
-- * An 'ExpirationClaim' of 1 hour from the current system time.
-- * An 'IssuedAtClaim' of the current system time.
-- * A 'NotBeforeClaim' of the current system time.
--
-- The default 'Footer' and 'ImplicitAssertion' is 'Nothing'.
getDefaultBuildTokenParams :: IO BuildTokenParams
getDefaultBuildTokenParams = do
  now <- getCurrentTime
  let hourInSeconds = 3600
      exp = ExpirationClaim . Expiration $ addUTCTime (secondsToNominalDiffTime hourInSeconds) now
      iat = IssuedAtClaim (IssuedAt now)
      nbf = NotBeforeClaim (NotBefore now)
  pure BuildTokenParams
    { btpClaims = Claims.fromList [exp, iat, nbf]
    , btpFooter = Nothing
    , btpImplicitAssertion = Nothing
    }

-- | Error building a version 3 local PASETO token.
newtype V3LocalBuildError
  = -- | Encryption error.
    V3LocalBuildEncryptionError V3.EncryptionError
  deriving stock (Show, Eq)

-- | Render a 'V3LocalBuildError' as 'Text'.
renderV3LocalBuildError :: V3LocalBuildError -> Text
renderV3LocalBuildError err =
  case err of
    V3LocalBuildEncryptionError e -> V3.renderEncryptionError e

-- | Build a version 3 local token.
buildTokenV3Local :: BuildTokenParams -> SymmetricKey V3 -> ExceptT V3LocalBuildError IO (Token V3 Local)
buildTokenV3Local btp k =
  firstExceptT V3LocalBuildEncryptionError $
    V3.encrypt k btpClaims btpFooter btpImplicitAssertion
  where
    BuildTokenParams
      { btpClaims
      , btpFooter
      , btpImplicitAssertion
      } = btp

-- | Error building a version 3 public PASETO token.
newtype V3PublicBuildError
  = -- | Cryptographic signing error.
    V3PublicBuildSigningError V3.SigningError
  deriving stock (Show, Eq)

-- | Render a 'V3PublicBuildError' as 'Text'.
renderV3PublicBuildError :: V3PublicBuildError -> Text
renderV3PublicBuildError err =
  case err of
    V3PublicBuildSigningError e -> V3.renderSigningError e

-- | Build a version 3 public token.
buildTokenV3Public :: BuildTokenParams -> SigningKey V3 -> ExceptT V3PublicBuildError IO (Token V3 Public)
buildTokenV3Public btp sk =
  firstExceptT V3PublicBuildSigningError $
    V3.sign sk btpClaims btpFooter btpImplicitAssertion
  where
    BuildTokenParams
      { btpClaims
      , btpFooter
      , btpImplicitAssertion
      } = btp

-- | Build a version 4 local token.
buildTokenV4Local :: BuildTokenParams -> SymmetricKey V4 -> IO (Token V4 Local)
buildTokenV4Local btp k = V4.encrypt k btpClaims btpFooter btpImplicitAssertion
  where
    BuildTokenParams
      { btpClaims
      , btpFooter
      , btpImplicitAssertion
      } = btp

-- | Build a version 4 public token.
buildTokenV4Public :: BuildTokenParams -> SigningKey V4 -> Token V4 Public
buildTokenV4Public btp sk = V4.sign sk btpClaims btpFooter btpImplicitAssertion
  where
    BuildTokenParams
      { btpClaims
      , btpFooter
      , btpImplicitAssertion
      } = btp
