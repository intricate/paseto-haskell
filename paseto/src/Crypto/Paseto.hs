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
    -- ** Asymmetric keys
    -- *** Signing keys
  , SigningKey (..)
  , signingKeyToBytes
  , bytesToSigningKeyV3
  , bytesToSigningKeyV4
    -- *** Verification keys
  , VerificationKey (..)
  , verificationKeyToBytes
  , bytesToVerificationKeyV3
  , bytesToVerificationKeyV4
  , fromSigningKey

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
    -- ** Encoding and decoding
  , encode
  , ValidatedToken (..)
  , decodeAndValidateTokenV3Local
  , decodeAndValidateTokenV3Public
  , decodeAndValidateTokenV4Local
  , decodeAndValidateTokenV4Public
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
  , signingKeyToBytes
  , symmetricKeyToBytes
  , verificationKeyToBytes
  )
import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Crypto.Paseto.Token
  ( Footer (..), ImplicitAssertion (..), Payload (..), Token (..) )
import Crypto.Paseto.Token.Build
  ( BuildTokenParams (..)
  , buildTokenV3Local
  , buildTokenV3Public
  , buildTokenV4Local
  , buildTokenV4Public
  , getDefaultBuildTokenParams
  )
import Crypto.Paseto.Token.Encoding
  ( ValidatedToken (..)
  , decodeAndValidateTokenV3Local
  , decodeAndValidateTokenV3Public
  , decodeAndValidateTokenV4Local
  , decodeAndValidateTokenV4Public
  , encode
  )
import Crypto.Paseto.Token.Validation as Validation
