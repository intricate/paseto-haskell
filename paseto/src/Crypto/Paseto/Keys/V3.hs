{-# LANGUAGE PatternSynonyms #-}

-- | P384 ECDSA cryptographic keys.
module Crypto.Paseto.Keys.V3
  ( -- * Curve
    curveP384

    -- * Private key
  , PrivateKeyP384 (PrivateKeyP384)
  , unPrivateKeyP384
  , mkPrivateKeyP384
  , generatePrivateKeyP384
  , encodePrivateKeyP384
  , Internal.ScalarDecodingError (..)
  , Internal.renderScalarDecodingError
  , decodePrivateKeyP384
  -- ** Helpers
  , generateScalarP384
  , isScalarValidP384

    -- * Public key
  , PublicKeyP384 (PublicKeyP384)
  , unPublicKeyP384
  , mkPublicKeyP384
  , fromPrivateKeyP384
  , PointCompression (..)
  , encodePublicKeyP384
  , encodePublicKeyP384'
  , Internal.CompressedPointDecodingError (..)
  , Internal.UncompressedPointDecodingError (..)
  , PublicKeyP384DecodingError (..)
  , renderPublicKeyP384DecodingError
  , decodePublicKeyP384
  ) where

import qualified Crypto.Paseto.Keys.V3.Internal as Internal
import qualified Crypto.PubKey.ECC.ECDSA as ECC.ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import Data.Bifunctor ( bimap )
import Data.ByteArray ( ScrubbedBytes, constEq )
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Text ( Text )
import Prelude

-- | Elliptic curve 'ECC.SEC_p384r1'.
curveP384 :: ECC.Curve
curveP384 = ECC.getCurveByName ECC.SEC_p384r1

------------------------------------------------------------------------------
-- P384 private key
------------------------------------------------------------------------------

-- | Generate a random scalar on the curve 'ECC.SEC_p384r1'.
generateScalarP384 :: IO Integer
generateScalarP384 = ECC.scalarGenerate curveP384

-- | Whether a scalar is valid on the curve 'ECC.SEC_p384r1'.
isScalarValidP384 :: Integer -> Bool
isScalarValidP384 = Internal.isScalarValid curveP384

-- | ECDSA private key for curve 'ECC.SEC_p384r1'.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype PrivateKeyP384 = MkPrivateKeyP384
  { unPrivateKeyP384 :: ECC.ECDSA.PrivateKey }
  deriving newtype Show

instance Eq PrivateKeyP384 where
  PrivateKeyP384 (ECC.ECDSA.PrivateKey cx dx) == PrivateKeyP384 (ECC.ECDSA.PrivateKey cy dy) =
    Internal.encodeScalar cx dx `constEq` Internal.encodeScalar cy dy

pattern PrivateKeyP384 :: ECC.ECDSA.PrivateKey -> PrivateKeyP384
pattern PrivateKeyP384 pk <- MkPrivateKeyP384 pk

{-# COMPLETE PrivateKeyP384 #-}

-- | Construct a private key for curve 'ECC.SEC_p384r1'.
mkPrivateKeyP384 :: ECC.ECDSA.PrivateKey -> Maybe PrivateKeyP384
mkPrivateKeyP384 privKey@(ECC.ECDSA.PrivateKey curve d)
  | curveP384 == curve && isScalarValidP384 d = Just (MkPrivateKeyP384 privKey)
  | otherwise = Nothing

-- | Generate a private key for curve 'ECC.SEC_p384r1'.
generatePrivateKeyP384 :: IO PrivateKeyP384
generatePrivateKeyP384 =
  MkPrivateKeyP384 . (ECC.ECDSA.PrivateKey curveP384)
    <$> generateScalarP384

-- | Encode a private key into its binary format as defined in
-- [RFC 5915](https://tools.ietf.org/html/rfc5915), i.e. the @privateKey@
-- field described in
-- [section 3](https://datatracker.ietf.org/doc/html/rfc5915#section-3).
encodePrivateKeyP384 :: PrivateKeyP384 -> ScrubbedBytes
encodePrivateKeyP384 (PrivateKeyP384 (ECC.ECDSA.PrivateKey curve d)) =
  Internal.encodeScalar curve d

-- | Decode a private key from its binary format as defined in
-- [RFC 5915](https://tools.ietf.org/html/rfc5915), i.e. the @privateKey@
-- field described in
-- [section 3](https://datatracker.ietf.org/doc/html/rfc5915#section-3).
decodePrivateKeyP384 :: ScrubbedBytes -> Either Internal.ScalarDecodingError PrivateKeyP384
decodePrivateKeyP384 bs =
  MkPrivateKeyP384 . ECC.ECDSA.PrivateKey curve
    <$> Internal.decodeScalar curve bs
  where
    curve :: ECC.Curve
    curve = curveP384

------------------------------------------------------------------------------
-- P384 public key
------------------------------------------------------------------------------

-- | ECDSA public key for curve 'ECC.SEC_p384r1'.
newtype PublicKeyP384 = MkPublicKeyP384
  { unPublicKeyP384 :: ECC.ECDSA.PublicKey }
  deriving newtype (Show, Eq)

pattern PublicKeyP384 :: ECC.ECDSA.PublicKey -> PublicKeyP384
pattern PublicKeyP384 pk <- MkPublicKeyP384 pk

{-# COMPLETE PublicKeyP384 #-}

-- | Construct a public key for curve 'ECC.SEC_p384r1'.
mkPublicKeyP384 :: ECC.ECDSA.PublicKey -> Maybe PublicKeyP384
mkPublicKeyP384 pubKey@(ECC.ECDSA.PublicKey curve point)
  | curveP384 == curve && ECC.isPointValid curve point = Just (MkPublicKeyP384 pubKey)
  | otherwise = Nothing

-- | Construct the 'PublicKeyP384' which corresponds to a given
-- 'PrivateKeyP384'.
fromPrivateKeyP384 :: PrivateKeyP384 -> PublicKeyP384
fromPrivateKeyP384 (PrivateKeyP384 privateKey) =
  MkPublicKeyP384 (Internal.fromPrivateKey privateKey)

-- | Elliptic curve point compression.
data PointCompression
  = -- | Elliptic curve point should be compressed.
    PointCompressed
  | -- | Elliptic curve point should not be compressed.
    PointUncompressed
  deriving stock (Show, Eq)

-- | Encode an elliptic curve point into its binary format as defined by
-- [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
encodePublicKeyP384' :: PointCompression -> PublicKeyP384 -> ByteString
encodePublicKeyP384' compression (PublicKeyP384 (ECC.ECDSA.PublicKey c p)) =
  case c of
    ECC.CurveFP curvePrime ->
      case compression of
        PointCompressed -> Internal.encodePointCompressed curvePrime p
        PointUncompressed -> Internal.encodePointUncompressed curvePrime p
    _ -> error "encodePublicKeyP384: impossible: secp384r1 curve is not a prime curve"

-- | Encode an elliptic curve point into its compressed binary format as
-- defined by [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
encodePublicKeyP384 :: PublicKeyP384 -> ByteString
encodePublicKeyP384 = encodePublicKeyP384' PointCompressed

-- | Error decoding a public key for curve 'ECC.SEC_p384r1'.
data PublicKeyP384DecodingError
  = -- | Error decoding a compressed public key.
    PublicKeyP384DecodingCompressedError !Internal.CompressedPointDecodingError
  | -- | Error decoding an uncompressed public key.
    PublicKeyP384DecodingUncompressedError !Internal.UncompressedPointDecodingError
  deriving stock (Show, Eq)

-- | Render a 'PublicKeyP384DecodingError' as 'Text'.
renderPublicKeyP384DecodingError :: PublicKeyP384DecodingError -> Text
renderPublicKeyP384DecodingError err =
  case err of
    PublicKeyP384DecodingCompressedError e ->
      "Failed to decode compressed public key: "
        <> Internal.renderCompressedPointDecodingError e
    PublicKeyP384DecodingUncompressedError e ->
      "Failed to decode uncompressed public key: "
        <> Internal.renderUncompressedPointDecodingError e

-- | Decode a public key from either its compressed or uncompressed binary
-- format as defined by [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
decodePublicKeyP384 :: ByteString -> Either PublicKeyP384DecodingError PublicKeyP384
decodePublicKeyP384 bs
  | len == 49 = bimap PublicKeyP384DecodingCompressedError mkPk (Internal.decodePointCompressed curvePrime bs)
  | otherwise = bimap PublicKeyP384DecodingUncompressedError mkPk (Internal.decodePointUncompressed curvePrime bs)
  where
    len :: Int
    len = BS.length bs

    curve :: ECC.Curve
    curve = curveP384

    curvePrime :: ECC.CurvePrime
    curvePrime =
      case curve of
        ECC.CurveFP c -> c
        _ -> error "decodePublicKeyP384: impossible: secp384r1 curve is not a prime curve"

    mkPk :: ECC.Point -> PublicKeyP384
    mkPk = MkPublicKeyP384 . (ECC.ECDSA.PublicKey curve)
