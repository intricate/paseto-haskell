module Crypto.Paseto.Keys.V3.Internal
  ( isScalarValid
  , encodeScalar
  , ScalarDecodingError (..)
  , renderScalarDecodingError
  , decodeScalar

  , encodePointUncompressed
  , encodePointCompressed
  , UncompressedPointDecodingError (..)
  , decodePointUncompressed
  , CompressedPointDecodingError (..)
  , decodePointCompressed
  , fromPrivateKey
  ) where

import Control.Monad ( when )
import qualified Crypto.Number.Basic as Crypto.Number
import qualified Crypto.Number.ModArithmetic as Crypto.Number
import qualified Crypto.Number.Serialize as Crypto.Number
import qualified Crypto.PubKey.ECC.ECDSA as ECC.ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import Data.ByteArray ( ScrubbedBytes )
import qualified Data.ByteArray as BA
import Data.ByteString ( ByteString )
import qualified Data.ByteString as BS
import Data.Text ( Text )
import qualified Data.Text as T
import Data.Word ( Word8 )
import Prelude

curveOrderBytes :: ECC.Curve -> Int
curveOrderBytes curve =
  (Crypto.Number.numBits (ECC.ecc_n $ ECC.common_curve curve) + 7) `div` 8

-- | Whether an elliptic curve scalar value is valid.
isScalarValid :: ECC.Curve -> Integer -> Bool
isScalarValid curve s = s > 0 && s < n
  where
    n :: Integer
    n = (ECC.ecc_n $ ECC.common_curve curve)

-- | Encode an elliptic curve scalar value.
encodeScalar :: ECC.Curve -> Integer -> ScrubbedBytes
encodeScalar curve = Crypto.Number.i2ospOf_ (curveOrderBytes curve)

-- | Error decoding a scalar value.
data ScalarDecodingError
  = -- | Invalid scalar length.
    ScalarDecodingInvalidLengthError
      -- | Expected length
      !Int
      -- | Actual length
      !Int
  | -- | Decoded scalar is invalid for the curve.
    ScalarDecodingInvalidError
  deriving stock (Show, Eq)

-- | Render a 'ScalarDecodingError' as 'Text'.
renderScalarDecodingError :: ScalarDecodingError -> Text
renderScalarDecodingError err =
  case err of
    ScalarDecodingInvalidLengthError expected actual ->
      "Decoded scalar value is of length "
        <> T.pack (show actual)
        <> ", but was expected to be "
        <> T.pack (show expected)
        <> "."
    ScalarDecodingInvalidError -> "Decoded scalar value is invalid for the curve."

-- | Decode an elliptic curve scalar value.
decodeScalar :: ECC.Curve -> ScrubbedBytes -> Either ScalarDecodingError Integer
decodeScalar curve bs
  | expectedLen /= actualLen = Left (ScalarDecodingInvalidLengthError expectedLen actualLen)
  | otherwise =
      let s = Crypto.Number.os2ip bs
      in if isScalarValid curve s then Right s else Left ScalarDecodingInvalidError
  where
    expectedLen :: Int
    expectedLen = curveOrderBytes curve

    actualLen :: Int
    actualLen = BA.length bs

-- | Encode an elliptic curve point into its uncompressed binary format as
-- defined by [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
--
-- Note that this function will only accept a point on an elliptic curve over
-- 𝔽p (i.e. 'ECC.CurvePrime').
encodePointUncompressed :: ECC.CurvePrime -> ECC.Point -> ByteString
encodePointUncompressed curvePrime point
  | ECC.isPointValid curve point =
      case point of
        ECC.Point x y -> do
          let size = ECC.curveSizeBits (ECC.CurveFP curvePrime) `div` 8
          BS.concat
            [ BS.singleton 0x04
            , Crypto.Number.i2ospOf_ size x
            , Crypto.Number.i2ospOf_ size y
            ]
        ECC.PointO -> error "encodePointUncompressed: cannot encode point at infinity"
  | otherwise = error "encodePointUncompressed: point is invalid"
  where
    curve :: ECC.Curve
    curve = ECC.CurveFP curvePrime

-- | Encode an elliptic curve point into its compressed binary format as
-- defined by [SEC 1](https://www.secg.org/sec1-v2.pdf).
--
-- Note that this function will only accept a point on an elliptic curve over
-- 𝔽p (i.e. 'ECC.CurvePrime').
--
-- Adapted from
-- [cryptonite issue #302](https://github.com/haskell-crypto/cryptonite/issues/302#issue-531003322).
encodePointCompressed :: ECC.CurvePrime -> ECC.Point -> ByteString
encodePointCompressed curvePrime point
  | ECC.isPointValid curve point =
      case point of
        -- We are using `i2ospOf_` because `curveSizeBits` ensures that
        -- the number won't have more than that many bytes.
        ECC.Point x y -> prefix y <> Crypto.Number.i2ospOf_ (ECC.curveSizeBits curve `div` 8) x
        ECC.PointO -> error "encodePointCompressed: cannot encode point at infinity"
  | otherwise = error "encodePointCompressed: point is invalid"
  where
    prefix :: Integer -> ByteString
    prefix y
      | odd y = BS.singleton 0x03
      | otherwise = BS.singleton 0x02

    curve :: ECC.Curve
    curve = ECC.CurveFP curvePrime

-- | Error decoding an uncompressed elliptic curve point.
data UncompressedPointDecodingError
  = -- | Prefix is not the expected value (@0x04@).
    UncompressedPointDecodingInvalidPrefixError
      -- | Invalid prefix which was encountered.
      !Word8
  | -- | Length of the provided point is invalid.
    UncompressedPointDecodingInvalidLengthError
      -- | Expected length
      !Int
      -- | Actual length
      !Int
  | -- | Point is invalid for the curve.
    UncompressedPointDecodingInvalidPointError !ECC.Point
  deriving stock (Show, Eq)

-- | Decode an elliptic curve point from its uncompressed binary format as
-- defined by [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
--
-- Note that this function will only decode a point on an elliptic curve over
-- 𝔽p (i.e. 'ECC.CurvePrime').
decodePointUncompressed :: ECC.CurvePrime -> ByteString -> Either UncompressedPointDecodingError ECC.Point
decodePointUncompressed curvePrime bs = do
  let expectedPointLen :: Int
      expectedPointLen = 1 + ((ECC.curveSizeBits (ECC.CurveFP curvePrime) `div` 8) * 2)

      actualPointLen :: Int
      actualPointLen = BS.length bs

  when
    (expectedPointLen /= actualPointLen)
    (Left $ UncompressedPointDecodingInvalidLengthError expectedPointLen actualPointLen)

  case BS.uncons bs of
    Nothing -> Left (UncompressedPointDecodingInvalidLengthError expectedPointLen 0)
    Just (prefix, rest)
      | prefix == 0x04 ->
          let (xBs, yBs) = BS.splitAt actualPointLen rest
              x = Crypto.Number.os2ip xBs
              y = Crypto.Number.os2ip yBs
              point = ECC.Point x y
          in if ECC.isPointValid (ECC.CurveFP curvePrime) point
            then Right point
            else Left (UncompressedPointDecodingInvalidPointError point)
      | otherwise -> Left (UncompressedPointDecodingInvalidPrefixError prefix)

-- | Error decoding a compressed elliptic curve point.
data CompressedPointDecodingError
  = -- | Prefix is not either of the expected values (@0x02@ or @0x03@).
    CompressedPointDecodingInvalidPrefixError
      -- | Invalid prefix which was encountered.
      !Word8
  | -- | Length of the provided compressed point is invalid.
    CompressedPointDecodingInvalidLengthError
      -- | Expected length
      !Int
      -- | Actual length
      !Int
  | -- | Failed to find the modular square root of a value.
    CompressedPointDecodingModularSquareRootError
  | -- | Point is invalid for the curve.
    CompressedPointDecodingInvalidPointError !ECC.Point
  deriving stock (Show, Eq)

data EvenOrOddY
  = EvenY
  | OddY

toEvenOrOddY :: Word8 -> Maybe EvenOrOddY
toEvenOrOddY 0x02 = Just EvenY
toEvenOrOddY 0x03 = Just OddY
toEvenOrOddY _ = Nothing

-- | Decode an elliptic curve point from its compressed binary format as
-- defined by [SEC 1](https://www.secg.org/sec1-v2.pdf) and
-- [RFC 5480 section 2.2](https://datatracker.ietf.org/doc/html/rfc5480#section-2.2).
--
-- Note that this function will only decode a point on an elliptic curve over
-- 𝔽p (i.e. 'ECC.CurvePrime').
--
-- Thanks to
-- [cryptonite PR #303](https://github.com/haskell-crypto/cryptonite/pull/303),
-- there's a function that we can use to compute a square root modulo a prime
-- number ('Crypto.Number.squareRoot').
decodePointCompressed :: ECC.CurvePrime -> ByteString -> Either CompressedPointDecodingError ECC.Point
decodePointCompressed curvePrime@(ECC.CurvePrime p curveCommon) bs = do
  let expectedCompressedPointLen :: Int
      expectedCompressedPointLen = 1 + (ECC.curveSizeBits (ECC.CurveFP curvePrime) `div` 8)

      actualCompressedPointLen :: Int
      actualCompressedPointLen = BS.length bs

  when
    (expectedCompressedPointLen /= actualCompressedPointLen)
    (Left $ CompressedPointDecodingInvalidLengthError expectedCompressedPointLen actualCompressedPointLen)

  case BS.uncons bs of
    Just (prefix, rest) ->
      case toEvenOrOddY prefix of
        Nothing -> Left (CompressedPointDecodingInvalidPrefixError prefix)
        Just evenOrOddY -> do
          let x :: Integer
              x = Crypto.Number.os2ip rest

              b :: Integer
              b = ECC.ecc_b curveCommon

          y <-
            case Crypto.Number.squareRoot p ((x ^ (3 :: Integer)) - (x * 3) + b) of
              Nothing -> Left CompressedPointDecodingModularSquareRootError
              Just y' ->
                case (evenOrOddY, odd y') of
                  (EvenY, True) -> Right (p - y')
                  (OddY, False) -> Right (p - y')
                  _ -> Right y'

          let point :: ECC.Point
              point = ECC.Point x y
          if ECC.isPointValid (ECC.CurveFP curvePrime) point
            then Right point
            else Left (CompressedPointDecodingInvalidPointError point)
    Nothing ->
      -- This should be impossible since we checked the length beforehand.
      Left (CompressedPointDecodingInvalidLengthError expectedCompressedPointLen 0)

-- | Construct the 'ECC.ECDSA.PublicKey' which corresponds to a given
-- 'ECC.ECDSA.PrivateKey'.
fromPrivateKey :: ECC.ECDSA.PrivateKey -> ECC.ECDSA.PublicKey
fromPrivateKey (ECC.ECDSA.PrivateKey curve d) =
  ECC.ECDSA.PublicKey curve (ECC.pointBaseMul curve d)
