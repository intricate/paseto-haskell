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
    -- | ==== Errors
  , ScalarDecodingError (..)
  , renderScalarDecodingError
    -- *** Verification keys
  , VerificationKey (..)
  , verificationKeyToBytes
  , bytesToVerificationKeyV3
  , bytesToVerificationKeyV4
  , fromSigningKey
    -- | ==== Errors
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
    -- | === Errors
  , V3LocalBuildError (..)
  , renderV3LocalBuildError
  , V3PublicBuildError (..)
  , renderV3PublicBuildError
    -- ** Encoding and decoding #encodingDecoding#
  , encode
  , ValidatedToken (..)
  , decodeTokenV3Local
  , decodeTokenV3Public
  , decodeTokenV4Local
  , decodeTokenV4Public
    -- | === Errors
  , CommonDecodingError (..)
  , renderCommonDecodingError
  , V3LocalDecodingError (..)
  , renderV3LocalDecodingError
  , V3PublicDecodingError (..)
  , renderV3PublicDecodingError
  , V4LocalDecodingError (..)
  , renderV4LocalDecodingError
  , V4PublicDecodingError (..)
  , renderV4PublicDecodingError
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
    -- *** Custom claim keys
  , UnregisteredClaimKey
  , mkUnregisteredClaimKey
  , renderUnregisteredClaimKey
    -- ** Validation
    -- *** Rules
  , ValidationRule (..)
  , ClaimMustExist (..)
    -- **** Default rules
  , getDefaultValidationRules
    -- **** Simple rules
  , forAudience
  , identifiedBy
  , issuedBy
  , notExpired
  , subject
  , validAt
  , customClaimEq
    -- | === Errors
  , ValidationError (..)
  , renderValidationError
  , renderValidationErrors
    -- ** Unsafe parsers
    -- $parsers
  , parseTokenV3Local
  , parseTokenV3Public
  , parseTokenV4Local
  , parseTokenV4Public
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
  , renderV4PublicDecodingError
  )
import Crypto.Paseto.Token.Parser
  ( parseTokenV3Local
  , parseTokenV3Public
  , parseTokenV4Local
  , parseTokenV4Public
  )
import Crypto.Paseto.Token.Validation
  ( ClaimMustExist (..)
  , ValidationError (..)
  , ValidationRule (..)
  , customClaimEq
  , forAudience
  , getDefaultValidationRules
  , identifiedBy
  , issuedBy
  , notExpired
  , renderValidationError
  , renderValidationErrors
  , subject
  , validAt
  )

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

-- $parsers
--
-- Note that these parsers are considered __unsafe__ as they /do not/ perform
-- any kind of token validation, cryptographic or otherwise. They simply
-- ensure that the input /looks like/ a well-formed token.
--
-- For typical usage, one should use the decoding functions that perform
-- parsing, cryptographic verification, and validation from the
-- [encoding and decoding](#g:encodingDecoding) section.
--
-- As a result, you should only use these unsafe parsers in specific
-- situations where you really know what you're doing. For example, they can
-- be useful in situations where one wants to parse some information out of a
-- token's footer without first needing to decrypt or verify the token. For
-- more information on this particular scenario, see
-- [Key-ID Support](https://github.com/paseto-standard/paseto-spec/blob/af79f25908227555404e7462ccdd8ce106049469/docs/02-Implementation-Guide/01-Payload-Processing.md#key-id-support)
-- in the PASETO specification.
