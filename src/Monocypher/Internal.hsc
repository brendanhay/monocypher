{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

module Monocypher.Internal where

import Data.ByteString (ByteString)
import Data.Monoid     ((<>))

import Foreign.Ptr (Ptr)
import Foreign.ForeignPtr    (ForeignPtr)

import qualified Data.Map                  as Map
import qualified Language.C.Inline.Context as C
import qualified Language.C.Types          as C

#include "monocypher.h"

context :: C.Context
context = mempty { C.ctxTypesTable = types } <> C.bsCtx <> C.baseCtx

types :: C.TypesTable
types = Map.fromList
    [ (C.TypeName "crypto_blake2b_ctx",  [t| Blake2b  |])
    ]

newtype PublicKey = PublicKey { unsafePublicKey :: ByteString }
newtype SharedKey = SharedKey { unsafeSharedKey :: ByteString }
newtype SecretKey = SecretKey { unsafeSecretKey :: ByteString }

newtype MAC   = MAC   ByteString
newtype Nonce = Nonce ByteString
newtype Salt  = Salt  ByteString
newtype AD    = AD    { getAD :: ByteString }

newtype Digest    = Digest    ByteString
newtype Signature = Signature ByteString
newtype Hash      = Hash      ByteString

newtype Plaintext  = Plaintext  ByteString
newtype Ciphertext = Ciphertext ByteString
newtype Password   = Password   ByteString

newtype Blake2b  = Blake2b (ForeignPtr Blake2b)

blake2bSize :: Int
blake2bSize = (#size crypto_blake2b_ctx)
