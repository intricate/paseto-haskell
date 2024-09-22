-- | This module is the recommended entry point for this library.
module Crypto.Paseto
  ( -- * Mode
    Version (..)
  , Purpose (..)

    -- * Keys
    -- ** Symmetric keys
  , SymmetricKey (..)
  , symmetricKeyToBytes
  , bytesToSymmetricKeyV3
  , bytesToSymmetricKeyV4
  , generateSymmetricKeyV3
  , generateSymmetricKeyV4
    -- ** Asymmetric keys
    -- *** Signing keys
  , SigningKey (..)
  , signingKeyToBytes
  , bytesToSigningKeyV3
  , bytesToSigningKeyV4
  , generateSigningKeyV3
  , generateSigningKeyV4
    -- **** Errors
  , ScalarDecodingError (..)
  , renderScalarDecodingError
    -- *** Verification keys
  , VerificationKey (..)
  , verificationKeyToBytes
  , bytesToVerificationKeyV3
  , bytesToVerificationKeyV4
  , fromSigningKey
    -- **** Errors
  , PublicKeyP384DecodingError (..)
  , renderPublicKeyP384DecodingError

    -- * Tokens
  , Token (..)
  , Payload (..)
  , Footer (..)
  , ImplicitAssertion (..)
    -- ** Construction
  , BuildTokenParams (..)
  , getDefaultBuildTokenParams
  , buildTokenV3Local
  , buildTokenV3Public
  , buildTokenV4Local
  , buildTokenV4Public
    -- *** Errors
  , V3LocalBuildError (..)
  , renderV3LocalBuildError
  , V3PublicBuildError (..)
  , renderV3PublicBuildError
    -- ** Encoding and decoding
  , encode
  , ValidatedToken (..)
  , decodeTokenV3Local
  , decodeTokenV3Public
  , decodeTokenV4Local
  , decodeTokenV4Public
    -- *** Errors
  , CommonDecodingError (..)
  , renderCommonDecodingError
  , V3LocalDecodingError (..)
  , renderV3LocalDecodingError
  , V3PublicDecodingError (..)
  , renderV3PublicDecodingError
  , V4LocalDecodingError (..)
  , renderV4LocalDecodingError
  , V4PublicDecodingError (..)
    -- ** Claims
    -- *** Container type
    -- $claimsContainer
  , Claims
    -- *** Claim types
  , Claim (..)
  , Issuer (..)
  , Subject (..)
  , Audience (..)
  , Expiration (..)
  , renderExpiration
  , NotBefore (..)
  , renderNotBefore
  , IssuedAt (..)
  , renderIssuedAt
  , TokenIdentifier (..)
    -- *** Custom/unregistered claim keys
  , UnregisteredClaimKey
  , mkUnregisteredClaimKey
  , renderUnregisteredClaimKey
    -- ** Validation
  , module Validation
  ) where

import Crypto.Paseto.Keys
  ( SigningKey (..)
  , SymmetricKey (..)
  , VerificationKey (..)
  , bytesToSigningKeyV3
  , bytesToSigningKeyV4
  , bytesToSymmetricKeyV3
  , bytesToSymmetricKeyV4
  , bytesToVerificationKeyV3
  , bytesToVerificationKeyV4
  , fromSigningKey
  , generateSigningKeyV3
  , generateSigningKeyV4
  , generateSymmetricKeyV3
  , generateSymmetricKeyV4
  , signingKeyToBytes
  , symmetricKeyToBytes
  , verificationKeyToBytes
  )
import Crypto.Paseto.Keys.V3
  ( PublicKeyP384DecodingError (..)
  , ScalarDecodingError (..)
  , renderPublicKeyP384DecodingError
  , renderScalarDecodingError
  )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Crypto.Paseto.Token
  ( Footer (..), ImplicitAssertion (..), Payload (..), Token (..) )
import Crypto.Paseto.Token.Build
  ( BuildTokenParams (..)
  , V3LocalBuildError (..)
  , V3PublicBuildError (..)
  , buildTokenV3Local
  , buildTokenV3Public
  , buildTokenV4Local
  , buildTokenV4Public
  , getDefaultBuildTokenParams
  , renderV3LocalBuildError
  , renderV3PublicBuildError
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
  , renderExpiration
  , renderIssuedAt
  , renderNotBefore
  , renderUnregisteredClaimKey
  )
import Crypto.Paseto.Token.Claims ( Claims )
import Crypto.Paseto.Token.Encoding
  ( CommonDecodingError (..)
  , V3LocalDecodingError (..)
  , V3PublicDecodingError (..)
  , V4LocalDecodingError (..)
  , V4PublicDecodingError (..)
  , ValidatedToken (..)
  , decodeTokenV3Local
  , decodeTokenV3Public
  , decodeTokenV4Local
  , decodeTokenV4Public
  , encode
  , renderCommonDecodingError
  , renderV3LocalDecodingError
  , renderV3PublicDecodingError
  , renderV4LocalDecodingError
  )
import Crypto.Paseto.Token.Validation as Validation

-- $claimsContainer
--
-- Collection of PASETO token claims.
--
-- Note that we only re-export the 'Claims' type from this module as the rest
-- of the API contains functions which may conflict with those in "Prelude"
-- and other container implementations such as "Data.Map".
--
-- If you need access to those other functions, it's recommended to import
-- "Crypto.Paseto.Token.Claims" qualified. For example:
--
-- @
-- import qualified Crypto.Paseto.Token.Claims as Claims
-- @
