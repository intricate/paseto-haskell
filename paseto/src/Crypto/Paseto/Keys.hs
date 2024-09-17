{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | PASETO cryptographic keys.
module Crypto.Paseto.Keys
  ( -- * Symmetric keys
    SymmetricKey (..)
  , symmetricKeyToBytes
  , bytesToSymmetricKeyV3
  , bytesToSymmetricKeyV4

    -- * Asymmetric keys
    -- ** Signing keys
  , SigningKey (..)
  , signingKeyToBytes
  , bytesToSigningKeyV3
  , bytesToSigningKeyV4
    -- ** Verification keys
  , VerificationKey (..)
  , verificationKeyToBytes
  , bytesToVerificationKeyV3
  , bytesToVerificationKeyV4
  , fromSigningKey
  ) where

import qualified Crypto.Error as Crypto
import qualified Crypto.Paseto.Keys.V3 as V3
import Crypto.Paseto.Mode ( Version (..) )
import Crypto.Paseto.ScrubbedBytes ( ScrubbedBytes32 (..), mkScrubbedBytes32 )
import qualified Crypto.PubKey.Ed25519 as Crypto.Ed25519
import Data.ByteArray ( ScrubbedBytes, constEq )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import Prelude

------------------------------------------------------------------------------
-- Symmetric keys
------------------------------------------------------------------------------

-- | Symmetric key.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
data SymmetricKey v where
  -- | Version 3 symmetric key.
  SymmetricKeyV3 :: !ScrubbedBytes32 -> SymmetricKey V3

  -- | Version 4 symmetric key.
  SymmetricKeyV4 :: !ScrubbedBytes32 -> SymmetricKey V4

instance Eq (SymmetricKey v) where
  SymmetricKeyV3 x == SymmetricKeyV3 y = x `constEq` y
  SymmetricKeyV4 x == SymmetricKeyV4 y = x `constEq` y

-- | Get the raw bytes associated with a symmetric key.
symmetricKeyToBytes :: SymmetricKey v -> ScrubbedBytes
symmetricKeyToBytes k =
  case k of
    SymmetricKeyV3 (ScrubbedBytes32 bs) -> bs
    SymmetricKeyV4 (ScrubbedBytes32 bs) -> bs

-- | Construct a version 3 symmetric key from bytes.
--
-- If the provided byte string does not have a length of @32@ (@256@ bits),
-- 'Nothing' is returned.
bytesToSymmetricKeyV3 :: ScrubbedBytes -> Maybe (SymmetricKey V3)
bytesToSymmetricKeyV3 = (SymmetricKeyV3 <$>) . mkScrubbedBytes32

-- | Construct a version 4 symmetric key from bytes.
--
-- If the provided byte string does not have a length of @32@ (@256@ bits),
-- 'Nothing' is returned.
bytesToSymmetricKeyV4 :: ScrubbedBytes -> Maybe (SymmetricKey V4)
bytesToSymmetricKeyV4 = (SymmetricKeyV4 <$>) . mkScrubbedBytes32

------------------------------------------------------------------------------
-- Asymmetric keys
------------------------------------------------------------------------------

-- | Signing key (also known as a private\/secret key).
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
data SigningKey v where
  -- | Version 3 signing key.
  SigningKeyV3 :: !V3.PrivateKeyP384 -> SigningKey V3

  -- | Version 3 signing key.
  SigningKeyV4 :: !Crypto.Ed25519.SecretKey -> SigningKey V4

instance Eq (SigningKey v) where
  x == y = signingKeyToBytes x `constEq` signingKeyToBytes y

-- | Get the raw bytes associated with a signing key.
signingKeyToBytes :: SigningKey v -> ScrubbedBytes
signingKeyToBytes sk =
  case sk of
    SigningKeyV3 k -> V3.encodePrivateKeyP384 k
    SigningKeyV4 k -> BA.convert k

-- | Construct a version 3 signing key from bytes.
bytesToSigningKeyV3 :: ScrubbedBytes -> Either V3.ScalarDecodingError (SigningKey V3)
bytesToSigningKeyV3 bs = SigningKeyV3 <$> V3.decodePrivateKeyP384 bs

-- | Construct a version 4 signing key from bytes.
bytesToSigningKeyV4 :: ScrubbedBytes -> Maybe (SigningKey V4)
bytesToSigningKeyV4 bs =
  SigningKeyV4
    <$> Crypto.maybeCryptoError (Crypto.Ed25519.secretKey bs)

-- | Verification key (also known as a public key).
data VerificationKey v where
  -- | Version 3 verification key.
  VerificationKeyV3 :: !V3.PublicKeyP384 -> VerificationKey V3

  -- | Version 4 verification key.
  VerificationKeyV4 :: !Crypto.Ed25519.PublicKey -> VerificationKey V4

deriving instance Eq (VerificationKey v)

-- | Get the raw bytes associated with a verification key.
verificationKeyToBytes :: VerificationKey v -> ByteString
verificationKeyToBytes vk =
  case vk of
    VerificationKeyV3 k -> V3.encodePublicKeyP384 k
    VerificationKeyV4 k -> BA.convert k

-- | Construct a version 3 verification key from bytes.
--
-- The input 'ByteString' is expected to be formatted as either a compressed
-- or uncompressed elliptic curve public key as defined by
-- [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
bytesToVerificationKeyV3 :: ByteString -> Either V3.PublicKeyP384DecodingError (VerificationKey V3)
bytesToVerificationKeyV3 bs = VerificationKeyV3 <$> V3.decodePublicKeyP384 bs

-- | Construct a version 4 verification key from bytes.
bytesToVerificationKeyV4 :: ByteString -> Maybe (VerificationKey V4)
bytesToVerificationKeyV4 bs =
  VerificationKeyV4
    <$> Crypto.maybeCryptoError (Crypto.Ed25519.publicKey bs)

-- | Get the 'VerificationKey' which corresponds to a given 'SigningKey'.
fromSigningKey :: SigningKey v -> VerificationKey v
fromSigningKey sk =
  case sk of
    SigningKeyV3 k -> VerificationKeyV3 (V3.fromPrivateKeyP384 k)
    SigningKeyV4 k -> VerificationKeyV4 (Crypto.Ed25519.toPublic k)
