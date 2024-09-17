{-# LANGUAGE TemplateHaskell #-}

module Test.Crypto.Paseto.PreAuthenticationEncoding
  ( tests
  ) where

import Crypto.Paseto.PreAuthenticationEncoding ( decode, encode )
import Data.ByteString ( ByteString )
import Hedgehog
  ( Gen, Property, checkParallel, discover, forAll, property, tripping )
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Prelude
import Test.Golden ( goldenTestPae )

tests :: IO Bool
tests = checkParallel $$(discover)

------------------------------------------------------------------------------
-- Properties
------------------------------------------------------------------------------

-- | Test that 'encode' and 'decode' round trip.
prop_roundTrip_encodeDecode :: Property
prop_roundTrip_encodeDecode = property $ do
  pieces <- forAll genPieces
  tripping pieces encode decode

prop_golden_example1 :: Property
prop_golden_example1 = goldenTestPae goldenExample1 "test/golden/pae/example1/golden.bin"

prop_golden_example2 :: Property
prop_golden_example2 = goldenTestPae goldenExample2 "test/golden/pae/example2/golden.bin"

prop_golden_example3 :: Property
prop_golden_example3 = goldenTestPae goldenExample3 "test/golden/pae/example3/golden.bin"

prop_golden_example4 :: Property
prop_golden_example4 = goldenTestPae goldenExample4 "test/golden/pae/example4/golden.bin"

------------------------------------------------------------------------------
-- Generators
------------------------------------------------------------------------------

genPieces :: Gen [ByteString]
genPieces = Gen.list (Range.constant 0 256) $ Gen.bytes (Range.constant 0 256)

------------------------------------------------------------------------------
-- Golden examples
------------------------------------------------------------------------------

goldenExample1 :: [ByteString]
goldenExample1 = []

goldenExample2 :: [ByteString]
goldenExample2 = [""]

goldenExample3 :: [ByteString]
goldenExample3 = ["test"]

goldenExample4 :: [ByteString]
goldenExample4 =
  [ "test"
  , "1337"
  , "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  , ""
  , "\0\0\0\0\0\0\0\0\0\0\0aaaaaaaa\0\0\0\0\0\0\0\0\0\0\0aa\0\0\0bbbb\0\0aa31337"
  , "The quick brown fox jumps over the lazy dog"
  , "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus sit amet fringilla tellus. Nunc sem magna, tristique non tortor eu, placerat consequat libero. Vivamus sed facilisis tellus. Phasellus aliquam tortor sit amet nisi ultricies tincidunt. In id egestas mauris. Vivamus ullamcorper at erat euismod feugiat. Duis eleifend dui ac mattis imperdiet. Ut faucibus risus eget molestie blandit.\n\nInterdum et malesuada fames ac ante ipsum primis in faucibus. Nullam gravida tempus tortor, id vulputate ex placerat ut. Integer venenatis, mauris non vehicula cursus, est elit porttitor dui, ac tempus mi neque vitae erat. Nulla mi mi, ornare vel molestie sit amet, consequat a odio. Aliquam auctor volutpat nisl eu efficitur. Integer nec facilisis mauris. Etiam blandit risus nisl, et ornare purus blandit quis. Vivamus fermentum commodo nunc nec rutrum.\n\nSed non mi leo. Nam non ligula id nulla rhoncus tempor. Phasellus arcu libero, euismod in ultricies nec, viverra ut diam. Aenean luctus tortor vitae elit laoreet feugiat. Sed tempor ex tincidunt arcu interdum pretium. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Nunc eleifend, odio ut dictum ornare, augue ante blandit ligula, ac elementum elit elit at enim. Duis lectus tellus, sodales vel finibus quis, lacinia in lectus. Donec faucibus auctor justo, pharetra convallis dolor sagittis id.\n\nSuspendisse at pulvinar ligula. Suspendisse id lorem ex. Aliquam ac sapien dolor. Suspendisse mattis lectus felis, eu volutpat metus imperdiet nec. Donec luctus porttitor scelerisque. Morbi convallis, felis ut pellentesque posuere, tortor dui imperdiet felis, sit amet pretium nunc neque ac felis. Quisque maximus, ex vel fringilla porta, purus dolor condimentum dui, a pulvinar ante augue vel ante.\n\nVestibulum urna elit, lacinia sed ipsum eget, malesuada mattis erat. Aliquam diam magna, vehicula fermentum ultrices a, malesuada non turpis. Sed interdum lectus sit amet felis porttitor, at rhoncus tortor eleifend. Proin sed gravida lectus, at varius nisi. Nam eu eros eu tortor fermentum maximus. Pellentesque vel diam eu magna sodales luctus vitae non odio. Ut dapibus, urna tincidunt elementum tincidunt, metus mauris lobortis mauris, eget bibendum nisl libero quis turpis. Sed malesuada ex eget porta cursus."
  ]
