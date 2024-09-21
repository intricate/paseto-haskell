module Test.Gen
  ( genAesonString
  , genUTCTime
  , genNominalDiffTime
  ) where

import qualified Data.Aeson as Aeson
import Data.Time.Calendar.OrdinalDate ( Day, fromOrdinalDate )
import Data.Time.Clock
  ( DiffTime, NominalDiffTime, UTCTime (..), secondsToDiffTime )
import Hedgehog ( Gen, Range )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genAesonString :: Gen Aeson.Value
genAesonString = Aeson.String <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

genUTCTime :: Gen UTCTime
genUTCTime = UTCTime <$> genDay <*> genDiffTime
  where
    genDay :: Gen Day
    genDay =
      fromOrdinalDate
        <$> Gen.integral (Range.constant 0 3000)
        <*> Gen.int (Range.constant 1 365)

    genDiffTime :: Gen DiffTime
    genDiffTime = secondsToDiffTime <$> Gen.integral (Range.constant 0 86400)

genNominalDiffTime
  :: Range Integer
  -- ^ Range of seconds.
  -> Gen NominalDiffTime
genNominalDiffTime range = fromInteger <$> Gen.integral range
