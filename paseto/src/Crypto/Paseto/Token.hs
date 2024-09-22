{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

module Crypto.Paseto.Token
  ( Footer (..)

  , ImplicitAssertion (..)

  , Payload (..)

  , Token (..)
  , SomeToken (..)
  , toSomeToken
  ) where

import Crypto.Paseto.Mode ( Purpose (..), Version (..) )
import Data.ByteArray ( constEq )
import Data.ByteString ( ByteString )
import Prelude

-- | Footer consisting of unencrypted free-form data.
--
-- The footer's contents may be JSON or some other structured data, but it
-- doesn't have to be.
--
-- When a PASETO token is constructed, the footer is authenticated, but not
-- encrypted (i.e. its integrity is protected, but it is not made
-- confidential). In authenticated encryption schemes, this is referred to as
-- \"associated data\".
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype Footer = Footer
  { unFooter :: ByteString }
  deriving newtype (Show)

instance Eq Footer where
  Footer x == Footer y = x `constEq` y

-- | Unencrypted authenticated data which is not stored in the PASETO token.
--
-- When a PASETO token is constructed, the implicit assertion is
-- authenticated, but it is not stored in the token. This is useful if one
-- wants to associate some data that should remain confidential.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype ImplicitAssertion = ImplicitAssertion
  { unImplicitAssertion :: ByteString }
  deriving newtype (Show)

instance Eq ImplicitAssertion where
  ImplicitAssertion x == ImplicitAssertion y = x `constEq` y

-- | Raw PASETO token payload.
--
-- Note that this type's 'Eq' instance performs a constant-time equality
-- check.
newtype Payload = Payload
  { unPayload :: ByteString }
  deriving newtype (Show)

instance Eq Payload where
  Payload x == Payload y = x `constEq` y

-- | PASETO token parameterized by its protocol 'Version' and 'Purpose'.
data Token v p where
  -- | PASETO version 3 local token.
  TokenV3Local
    :: !Payload
    -- ^ Encrypted token payload.
    -> !(Maybe Footer)
    -- ^ Optional footer (associated data).
    -> Token V3 Local

  -- | PASETO version 3 public token.
  TokenV3Public
    :: !Payload
    -- ^ Signed token payload.
    -> !(Maybe Footer)
    -- ^ Optional footer (associated data).
    -> Token V3 Public

  -- | PASETO version 4 local token.
  TokenV4Local
    :: !Payload
    -- ^ Encrypted token payload.
    -> !(Maybe Footer)
    -- ^ Optional footer (associated data).
    -> Token V4 Local

  -- | PASETO version 4 public token.
  TokenV4Public
    :: !Payload
    -- ^ Signed token payload.
    -> !(Maybe Footer)
    -- ^ Optional footer (associated data).
    -> Token V4 Public

deriving instance Show (Token v p)

instance Eq (Token v p) where
  TokenV3Local px fx == TokenV3Local py fy = px == py && fx == fy
  TokenV3Public px fx == TokenV3Public py fy = px == py && fx == fy
  TokenV4Local px fx == TokenV4Local py fy = px == py && fx == fy
  TokenV4Public px fx == TokenV4Public py fy = px == py && fx == fy

-- | Some kind of PASETO token.
data SomeToken
  = SomeTokenV3Local !(Token V3 Local)
  | SomeTokenV3Public !(Token V3 Public)
  | SomeTokenV4Local !(Token V4 Local)
  | SomeTokenV4Public !(Token V4 Public)
  deriving stock (Show, Eq)

-- | Convert a 'Token' to a 'SomeToken'.
toSomeToken :: Token v p -> SomeToken
toSomeToken t =
  case t of
    TokenV3Local _ _ -> SomeTokenV3Local t
    TokenV3Public _ _ -> SomeTokenV3Public t
    TokenV4Local _ _ -> SomeTokenV4Local t
    TokenV4Public _ _ -> SomeTokenV4Public t
