module Test.Crypto.Paseto.Token.Validation.Gen
  ( genConstValidationRule
  ) where

import Crypto.Paseto.Token.Validation
  ( ValidationError (..), ValidationRule (..) )
import Hedgehog ( Gen )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude

genValidationCustomError :: Gen ValidationError
genValidationCustomError = ValidationCustomError <$> Gen.text (Range.constant 0 1024) Gen.unicodeAll

-- | Generate a simple 'ValidationRule' that either returns a 'Left'
-- 'ValidationCustomError' or '()' regardless of the claims value its given.
--
-- In addition to the generated rule, a 'Bool' value which indicates whether
-- success should be expected is also provided.
genConstValidationRule :: Gen (ValidationRule, Bool)
genConstValidationRule = do
  res <- Gen.either genValidationCustomError (pure ())
  case res of
    Left _ -> pure (ValidationRule (const res), False)
    Right _ -> pure (ValidationRule (const res), True)
