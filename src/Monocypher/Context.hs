{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TemplateHaskell   #-}

module Monocypher.Context where

import Data.Monoid ((<>))

import Monocypher.Types (Blake2b, Chacha20, Poly1305)

import qualified Data.Map                  as Map
import qualified Language.C.Inline         as C
import qualified Language.C.Inline.Context as C
import qualified Language.C.Types          as C

openContext :: C.Context
openContext =
  mconcat
      [ C.baseCtx
      , C.vecCtx
      , C.bsCtx
      , mempty { C.ctxTypesTable = typesTable }
      ]

-- FIXME: add types context for mac, ciphertext, nonce, key, plaintext?

typesTable :: C.TypesTable
typesTable = Map.fromList
    [ (C.TypeName "crypto_chacha_ctx",   [t| Chacha20 |])
    , (C.TypeName "crypto_poly1305_ctx", [t| Poly1305 |])
    , (C.TypeName "crypto_blake2b_ctx",  [t| Blake2b  |])
    ]
