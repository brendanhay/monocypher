{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE MultiParamTypeClasses    #-}
{-# LANGUAGE QuasiQuotes              #-}
{-# LANGUAGE ScopedTypeVariables      #-}
{-# LANGUAGE Strict                   #-}
{-# LANGUAGE TemplateHaskell          #-}
{-# LANGUAGE ViewPatterns             #-}

module Monocypher
    (
    -- * Authenticated encryption (XChacha20 + Poly1305)
    -- $authenticated_encryption
      lock
    , unlock

    -- * AEAD (Authenticated Encryption with Additional Data)
    -- $aead
    , lockAEAD
    , unlockAEAD

    -- * Diffie-Hellman key exchange (X25519 + HChacha20)
    -- $diffie_hellman
    , exchangeKey

    -- * Public key signatures (edDSA with curve25519 & Blake2b)
    -- $public_key_signatures
    , publicKey
    , sign
    , check

    -- * Cryptographic Hash (Blake2b)
    -- $blake2b

    -- ** Direct
    -- $blake2b_direct
    , blake2b

    -- ** Incremental
    -- $blake2b_incremental
    , blake2bInit
    , blake2bUpdate
    , blake2bFinal

    -- * Password key derivation (Argon2i)
    -- $pasword_key_derivation
    , argon2i

    -- * Constant time comparison
    -- $constant_time_comparison
    , ConstantTimeEq (..)

    , cryptoCompare
    , cryptoIsZeros

    -- * Types
    , PublicKey
    , SharedKey
    , SecretKey
    , MAC
    , Nonce
    , Plaintext
    , Ciphertext
    , Blake2b
    ) where

import Data.Bifunctor  (second)
import Data.ByteString (ByteString)
import Data.Word       (Word32, Word8)

import Monocypher.Internal

import Foreign.C.Types (CChar)
import Foreign.Ptr     (Ptr)

import qualified Data.ByteString        as BS
import qualified Data.ByteString.Unsafe as BS
import qualified Foreign.ForeignPtr     as C
import qualified Foreign.Marshal.Alloc  as C
import qualified Foreign.Marshal.Array  as C
import qualified Foreign.Ptr            as C
import qualified Foreign.Storable       as C
import qualified Language.C.Inline      as C

-- FIXME: Recreate the Monocypher test suite

C.context context

C.include "monocypher.h"

{- $authenticated_encryption

Authenticated encryption (XChacha20 + Poly1305)

Encryption makes your messages unreadable to eavesdroppers. Authentication
ascertain the origin and integrity of the messages you read.

Both are important. Without encryption, you give away all your secrets, and
without authentication, you can fall prey to forgeries (messages that look
legitimate, but actually come from the attacker). A clever attacker may even
leverage forgeries to steal your secrets.

/Always authenticate your messages./
-}

{- |
The inputs are:

__key__: a 32-byte session key, shared between you and the recipient. It must be
secret (unknown to the attacker) and random (unpredictable to the attacker). Of
course, one does not simply transmit this key over the network. There are less
suicidal ways to share session keys, such as meeting physically, or performing
a Diffie Hellman key exchange (described below).

__nonce__: a 24-byte a number, used only once with any given session key. It
doesn't have to be secret or random. But you must never reuse that number with
the same key. If you do, the attacker will have access to the XOR of 2
different messages, and the ability to forge messages in your stead.

The easiest (and recommended) way to generate this nonce is to use your OS's
random number generator (__\/dev\/urandom__ on UNIX systems). Don't worry about
accidental collisions, the nonce is big enough to make them virtually
impossible.

Don't use user space random number generators, they're error prone. You could
accidentally reuse the generator's internal state, duplicate the random stream,
and trigger a nonce reuse. Oops.

__plaintext__: the secret you want to send. Of course, it must be unknown to the
attacker. Keep in mind however that the length of the plaintext, unlike its
content, is not secret. Make sure your protocol doesn't leak secret information
with the length of messages. (It has happened before with variable-length voice
encoding software.) Solutions to mitigate this include constant-length
encodings and padding.

The outputs are:

__mac__: a 16-byte message authentication code (MAC), that only you could have
produced. (Of course, this guarantee goes out the window the nanosecond the
attacker somehow learns your session key, or sees 2 messages with the same
nonce. Seriously, don't reuse that nonce.)

Transmit this MAC over the network so the recipient can authenticate your
message.

__ciphertext__: the encrypted message (same length as the plaintext
message). Transmit it over the network so the recipient can decrypt and read
it.

/Note:/ ciphertext is allowed to have the same value as plaintext. If so,
encryption will happen in place.
-}
lock :: SecretKey -> Nonce -> Plaintext -> IO (MAC, Ciphertext)
lock (SecretKey key) (Nonce nonce) (Plaintext plain) =
    -- void crypto_lock(uint8_t        mac[16],
    --                  uint8_t       *ciphertext,
    --                  const uint8_t  key[32],
    --                  const uint8_t  nonce[24],
    --                  const uint8_t *plaintext, size_t text_size);

    let macLen    = 16
        cipherLen = BS.length plain
     in C.allocaArray macLen    $ \(macPtr    :: Ptr Word8) ->
        C.allocaArray cipherLen $ \(cipherPtr :: Ptr Word8) -> do
            [C.block|void {
                crypto_lock( $(uint8_t *macPtr)
                           , $(uint8_t *cipherPtr)
                           , $bs-ptr:key
                           , $bs-ptr:nonce
                           , $bs-ptr:plain, $bs-len:plain
                           );
            }|]

            macBS    <- BS.packCStringLen (C.castPtr macPtr,    macLen)
            cipherBS <- BS.packCStringLen (C.castPtr cipherPtr, cipherLen)

            pure (MAC macBS, Ciphertext cipherBS)

{- |
The flip side of the coin. The inputs are:

__key__: the session key. It's the same as the one used for authenticated
encryption.

__nonce__: the nonce that was used to encrypt this particular message. No
decryption is possible without it.

__mac__: the message authentication code produced by the sender. Integrity cannot
be ensured without it.

__ciphertext__: the encrypted text produced by the sender.

There are 2 outputs:

__plaintext__: The decrypted message (same length as the ciphertext).

/Note:/ plaintext is allowed to be the same as ciphertext. If so, decryption will
happen in place.

__return code__: 0 if all went well, -1 if the message was corrupted (either
accidentally or intentionally).

/Tip:/ always check your return code.

Unlocking proceeds in two steps: first, we authenticate the additional data and
the ciphertext with the provided MAC. If any of those three has been corrupted,
crypto_aead_unlock() returns -1 immediately, without decrypting the message. If
the message is genuine, crypto_aead_unlock() decrypts the ciphertext, then
returns 0.

/(Again, if someone gave away the session key or reused a nonce, detecting forgeries becomes impossible. Don't reuse the nonce.)/
-}
unlock :: SecretKey -> Nonce -> MAC -> Ciphertext -> IO (Maybe Plaintext)
unlock (SecretKey key) (Nonce nonce) (MAC mac) (Ciphertext cipher) =
    -- int crypto_unlock(uint8_t       *plaintext,
    --                   const uint8_t  key[32],
    --                   const uint8_t  nonce[24],
    --                   const uint8_t  mac[16],
    --                   const uint8_t *ciphertext, size_t text_size);

    let plainLen = BS.length cipher
     in C.allocaArray plainLen $ \(plainPtr :: Ptr Word8) -> do
            code <- [C.block|int {
                crypto_unlock( $(uint8_t *plainPtr)
                             , $bs-ptr:key
                             , $bs-ptr:nonce
                             , $bs-ptr:mac
                             , $bs-ptr:cipher, $bs-len:cipher
                             );
            }|]

            if code /= 0
                then pure Nothing
                else do
                    plain <- BS.packCStringLen (C.castPtr plainPtr, plainLen)
                    pure $! Just (Plaintext plain)

{- $aead
These functions have two additional parameters: ad and ad_size. They represent
additional data, that is authenticated, but not encrypted. Note: ad is
optional, and may be null if ad_size is zero. This can be useful if your
protocol somehow requires you to send unencrypted data.

Note: using those functions is discouraged: if the data you're transmitting is
worth authenticating, it's probably worth encrypting as well. Do so if you can,
using crypto_lock() and crypto_unlock().

If you must send unencrypted data, remember that you cannot trust
unauthenticated data. Including the length of the additional data. If you
transmit that length over the wire, you must authenticate it. (The easiest way
to do so is to append that length to the additional data before you call
crypto_aead_*()). If you don't, the attacker could provide a false length,
effectively moving the boundary between the additional data and the ciphertext.

If however the length of the additional data is implicit (fixed size) or
self-contained (length appending, null termination…), you don't need to
authenticate it explicitly.

(The crypto_aead_*() functions don't authenticate the length themselves for
simplicity, compatibility, and efficiency reasons: most of the time, the length
of the additional data is either fixed or self contained, and thus outside of
attacker control. It also makes them compatible with crypto_lock() and
crypto_unlock() when the size of the additional data is zero, and simplifies
the implementation.)
-}

lockAEAD :: SecretKey -> Nonce -> AD -> Plaintext -> IO (MAC, Ciphertext)
lockAEAD (SecretKey key) (Nonce nonce) (AD ad) (Plaintext plain) =
    -- void crypto_aead_lock(uint8_t        mac[16],
    --                       uint8_t       *cipher_text,
    --                       const uint8_t  key[32],
    --                       const uint8_t  nonce[24],
    --                       const uint8_t *ad        , size_t ad_size,
    --                       const uint8_t *plain_text, size_t text_size);

    let macLen    = 16
        cipherLen = BS.length plain
     in C.allocaArray macLen $ \(macPtr :: Ptr Word8) ->
        C.allocaArray cipherLen $ \(cipherPtr :: Ptr Word8) -> do
            [C.block|void {
                crypto_aead_lock( $(uint8_t *macPtr)
                                , $(uint8_t *cipherPtr)
                                , $bs-ptr:key
                                , $bs-ptr:nonce
                                , $bs-ptr:ad, $bs-len:ad
                                , $bs-ptr:plain, $bs-len:plain
                                );
            }|]

            mac    <- BS.packCStringLen (C.castPtr macPtr,    macLen)
            cipher <- BS.packCStringLen (C.castPtr cipherPtr, cipherLen)

            pure (MAC mac, Ciphertext cipher)

unlockAEAD :: SecretKey -> Nonce -> MAC -> AD -> Ciphertext -> IO (Maybe Plaintext)
unlockAEAD (SecretKey key) (Nonce nonce) (MAC mac) (AD ad) (Ciphertext cipher) =
    -- int crypto_aead_unlock(uint8_t       *plain_text,
    --                        const uint8_t  key[32],
    --                        const uint8_t  nonce[24],
    --                        const uint8_t  mac[16],
    --                        const uint8_t *ad         , size_t ad_size,
    --                        const uint8_t *cipher_text, size_t text_size);

    let plainLen = BS.length cipher
     in C.allocaArray plainLen $ \(plainPtr :: Ptr Word8) -> do
            code <- [C.block|int {
                crypto_unlock( $(uint8_t *plainPtr)
                             , $bs-ptr:key
                             , $bs-ptr:nonce
                             , $bs-ptr:mac
                             , $bs-ptr:ad, $bs-len:ad
                             , $bs-ptr:cipher, $bs-len:cipher
                             );
            }|]

            if code /= 0
                then pure Nothing
                else do
                    plain <- BS.packCStringLen (C.castPtr plainPtr, plainLen)
                    pure $! Just (Plaintext plain)

{- $diffie_hellman

Key exchange works thus: Alice and Bob each have a key pair (a secret key and a
public key). They know each other's public key, but they keep their own secret
key… secret. Key exchange works like this:

> shared_secret = get_shared_secret(Alice_public_key, Bob_secret_key)
>               = get_shared_secret(Bob_public_key, Alice_secret_key)

If Eve learns Alice's secret key, she could compute the shared secret between
Alice and anyone else (including Bob), allowing her to read and forge
correspondence. Protect your secret key.

Furthermore, Alice and Bob must know each other's public keys beforehand. If
they don't, and try to communicate those keys over an insecure channel, Eve
might intercept their communications and provide false public keys. There are
various ways to learn of each other's public keys (crypto parties, certificate
authorities, web of trust…), each with its advantages and drawbacks.
-}

{- |
Computes a shared key with your secret key and their public key, suitable for
the crypto_*lock() functions above. It performs a X25519 key exchange, then
hashes the shared secret (with HChacha20) to get a suitably random-looking
shared key.

Keep in mind that if either of your long term secret keys leaks, it may
compromise all past messages! If you want forward secrecy, you'll need to
exchange temporary public keys, then compute your shared secret with them. (How
that should be done, and the exact security guarantees are not clear to me at
the moment.)

The return code serves as a security check: there are a couple evil public keys
out there, that force the shared key to a known constant (the HCHacha20 of
zero). This never happens with legitimate public keys, but if the ones you
process aren't exactly trustworthy, watch out.

So, crypto_lock_key() returns -1 whenever it detects such an evil public
key. If all goes well, it returns zero.
-}
exchangeKey :: SecretKey -> PublicKey -> IO (Maybe SharedKey)
exchangeKey (SecretKey secret) (PublicKey public) =
    -- int crypto_key_exchange(u8       shared_key[32],
    --                         const u8 your_secret_key [32],
    --                         const u8 their_public_key[32]);

    let sharedLen = 32
     in C.allocaArray sharedLen $ \(sharedPtr :: Ptr Word8) -> do
            code <- [C.block|int {
                crypto_key_exchange( $(uint8_t *sharedPtr)
                                   , $bs-ptr:secret
                                   , $bs-ptr:public
                                   );
            }|]

            if code /= 0
                then pure Nothing
                else do
                    shared <- BS.packCStringLen (C.castPtr sharedPtr, sharedLen)
                    pure $! Just (SharedKey shared)

{- $public_key_signatures

Authenticated encryption with key exchange is not always enough.
Sometimes, you want to _broadcast_ a signature, in such a way that
_everybody_ can verify.

When you sign a message with your private key, anybody who knows your
public key can verify that you signed the message.  Obviously, any
attacker that gets a hold of your private key can sign messages in
your stead.  Protect your private key.

Monocypher provides public key signatures with a variant of ed25519,
which uses Blake2b as the hash instead of SHA-512.  SHA-512 is
provided as an option for compatibility with other systems.

Blake2b is the default because it is faster, more flexible, harder to
misuse than SHA-512, and already required by Argon2i.  Monocypher
needs only one hash, and that shall be Blake2b.

The reason why there's a SHA-512 option at all is official test
vectors.  Can't test signatures reliably without them.

Note that using Blake2b instead of SHA-512 does *not* block your
upgrade path to faster implementations: Floodyberry's [Donna][]
library provides blazing fast implementations that can work with
custom hashes.

[Donna]: https://github.com/floodyberry/ed25519-donna
-}

{- |
Deterministically computes a public key from the specified secret key.
Make sure the secret key is randomly selected. OS good. User space
bad.

By the way, these are _not_ the same as key exchange key pairs.
Maintain separate sets of keys for key exchange and signing.  There
are clever ways to unify those keys, but those aren't covered by
Monocypher.
-}
publicKey :: SecretKey -> IO PublicKey
publicKey (SecretKey secret) =
    -- void crypto_sign_public_key(uint8_t        public_key[32],
    --                             const uint8_t  secret_key[32]);

    let publicLen = 32
     in C.allocaArray publicLen $ \(publicPtr :: Ptr Word8) -> do
            [C.block|void {
                crypto_sign_public_key( $(uint8_t *publicPtr)
                                      , $bs-ptr:secret
                                      );
            }|]

            public <- BS.packCStringLen (C.castPtr publicPtr, publicLen)

            pure (PublicKey public)

{- |
Signs a message with your secret key.  The public key is optional, and
will be recomputed if you don't provide it. It's twice as slow,
though.
-}
sign :: SecretKey -> Maybe PublicKey -> ByteString -> IO Signature
sign (SecretKey secret) mpublic message =
    -- void crypto_sign(uint8_t        signature[64],
    --                  const uint8_t  secret_key[32],
    --                  const uint8_t  public_key[32], // optional, may be null
    --                  const uint8_t *message, size_t message_size);

    let sigLen = 64
     in C.allocaArray sigLen $ \(sigPtr :: Ptr Word8) ->
        useMaybeAsCStringLen (unsafePublicKey <$> mpublic) $ \(publicPtr, _) -> do
            [C.block|void {
                crypto_sign( $(uint8_t *sigPtr)
                           , $bs-ptr:secret
                           , $(char *publicPtr)
                           , $bs-ptr:message, $bs-len:message
                           );
            }|]

            signature <- BS.packCStringLen (C.castPtr sigPtr, sigLen)

            pure (Signature signature)

{- |
Checks that a given signature is genuine.  Returns 0 for legitimate
messages, -1 for forgeries.  Of course, if the attacker got a hold of
the matching private key, all bets are off.

A word of warning: this function does *not* run in constant time.  It
doesn't have to in most threat models, because nothing is secret:
everyone knows the public key, and the signature and message are
rarely secret.

If you want to ascertain the origin of a secret message, you may want
to use x25519 key exchange instead.
-}
check :: Signature -> PublicKey -> ByteString -> IO Bool
check (Signature signature) (PublicKey public) message = do
    -- int crypto_check(const uint8_t  signature[64],
    --                  const uint8_t  public_key[32],
    --                  const uint8_t *message, size_t message_size);

    code <- [C.block|int {
        crypto_check( $bs-ptr:signature
                    , $bs-ptr:public
                    , $bs-ptr:message, $bs-len:message
                    );
    }|]

    pure $! code == 0

{- $blake2b
Blake2b is a fast cryptographically secure hash, based on the ideas of
Chacha20.  It is faster than md5, yet just as secure as SHA-3.
-}

{- $blake2b_direct
The direct interface sports 2 functions:

    void crypto_blake2b_general(uint8_t       *digest, size_t digest_size,
                                const uint8_t *key   , size_t key_size,
                                const uint8_t *in    , size_t in_size);

    void crypto_blake2b(uint8_t digest[64], const uint8_t *in, size_t in_size);

The second one is a convenience function, which uses a 64 bytes hash
and no key (this is a good default).

If you use the first function, you can specify the size of the digest
(I'd advise against anything below 32-bytes), and use a secret key to
make the hash unpredictable —useful for message authentication codes.

(Note: Blake2b is immune to [length extension attacks][LEA], and as
such does not require any [specific precaution][HMAC].  It can
authenticate messages with a naive approach.  _However_, older hashes
are _not_ immune to such attacks, and _do_ require those precautions.)

[LEA]:  https://en.wikipedia.org/wiki/Length_extension_attack (Wikipedia)
[HMAC]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code (HMAC)

- `digest     `: The output digest.  Must have at least `digest_size` free bytes.
- `digest_size`: the length of the hash.  Must be between 1 and 64.
- `key_size   `: length of the key.       Must be between 0 and 64.
- `key        `: some secret key.         May be null if key_size is 0.

Any deviation from these invariants results in __undefined behaviour.__ Make
sure your inputs are correct.
-}

-- FIXME: 'Key' is variable here. does it have the same semantic meaning as
-- the other uses of?
blake2b :: ByteString -> IO Digest
blake2b input =
    -- void crypto_blake2b(uint8_t        digest[64],
    --                     const uint8_t *in, size_t in_size);

    let digestLen = 64
     in C.allocaArray digestLen $ \(digestPtr :: Ptr Word8) -> do
            [C.block|void {
                crypto_blake2b( $(uint8_t *digestPtr)
                              , $bs-ptr:input, $bs-len:input
                              );
            }|]

            digest <- BS.packCStringLen (C.castPtr digestPtr, digestLen)

            pure (Digest digest)

{- $blake2b_incremental
Incremental interfaces are useful to handle streams of data or large
files without using too much memory.  This interface uses 3 steps:

- initialisation, where we set up a context with the various hashing
  parameters;
- update, where we hash the message chunk by chunk, and keep the
  intermediary result in the context;
- and finalisation, where we produce the final digest.

There are 2 init functions, one update function, and one final function:

    void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t digest_size,
                                     const uint8_t      *key, size_t key_size);

    void crypto_blake2b_init(crypto_blake2b_ctx *ctx);

    void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                               const uint8_t      *in, size_t in_size);

    void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *digest);


The invariants of the parameters are the same as for
`crypto_blake2b_general()`: `digest_size` must be between 1 and 64,
`key_size` must be between 0 and 64.  Any bigger and you get undefined
behaviour.

`crypto_blake2b_init()` is a convenience init function, that specifies
a 64 bytes hash and no key.  This is a good default.

`crypto_blake2b_update()` computes your hash piece by piece.

`crypto_blake2b_final()` outputs the digest.

Here's how you can hash the concatenation of 3 chunks with the
incremental interface:

    uint8_t digest[64];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init  (&ctx);
    crypto_blake2b_update(&ctx, chunk1, chunk1_size);
    crypto_blake2b_update(&ctx, chunk2, chunk2_size);
    crypto_blake2b_update(&ctx, chunk3, chunk3_size);
    crypto_blake2b_final (&ctx, digest);
-}

-- import Control.Monad (MonadPlus(..))
-- import Control.Monad.Trans.Class (MonadTrans(..))
-- import System.IO (isEOF)

-- stdinLn :: (MonadIO m, MonadPlus m) => m String
-- stdinLn = do
--     eof <- liftIO isEOF
--     if eof
--         then mzero
--         else liftIO getLine `mplus` stdinL

blake2bInit :: IO Blake2b
blake2bInit = do
    -- void crypto_blake2b_init(crypto_blake2b_ctx *ctx);

    ptr <- C.mallocForeignPtrBytes blake2bSize

    C.withForeignPtr ptr $ \blake2bPtr ->
        [C.block|void {
            crypto_blake2b_init($(crypto_blake2b_ctx *blake2bPtr));
        }|]

    pure (Blake2b ptr)

blake2bUpdate :: Blake2b -> ByteString -> IO ()
blake2bUpdate = undefined
    -- void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
    --                            const uint8_t      *in, size_t in_size);

blake2bFinal :: Blake2b -> IO Digest
blake2bFinal = undefined
    -- void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *digest);
    -- uint8_t digest[64];
    -- crypto_blake2b_final (&ctx, digest);

{- $password_key_derivation
Storing passwords in plaintext is suicide.  Storing hashed and salted
passwords is better, but still very dangerous: passwords simply don't
have enough entropy to prevent a dedicated attacker from guessing them
by sheer brute force.

One way to prevent such attacks is to make sure hashing a password
takes too much resources for a brute force search to be effective.
Moreover, we'd like the attacker to spend as much resources for each
attempt as we do, even if they have access to dedicated silicon.

Argon2i is a resource intensive password key derivation scheme
optimised for the typical x86-like processor.  It runs in constant
time with respect to the contents of the password.

Typical applications are password checking (for online services), and
key derivation (so you can encrypt stuff).  You can use this for
instance to protect your private keys.

The version currently provided by Monocypher has no threading support,
so the degree of parallelism is currently limited to 1.  It's good
enough for most purposes anyway.
-}

{- |
- The minimum tag size is 4 bytes
- The minimum number of blocks is 8. (blocks are 1024 bytes big.)
- the work area must be big enough to hold the requested number of
  blocks, and suitably aligned for 64-bit integers.  Tip: just use
  `malloc()`.
- The minimum number of iterations is 1.
- The minimum salt size is 8 bytes.
- The key and additional data are optional.  They can be null if their
  respective size is zero.

Any deviation from these invariants may result in __undefined
behaviour.__

Recommended choice of parameters:

- If you need a key, use a 32 byte one.
- Do what you will with the additional data `ad`.
- Use a 32 byte tag to derive a 256-bit key.
- Put 128 bits of entropy in the salt.  16 random bytes work well.
- Use at least 3 iterations.  Argon2i is less safe with only one or
  two.  Otherwise, more memory is better than more iterations.

Use `crypto_memcmp()` to compare Argon2i outputs.  Argon2i is designed
to withstand offline attacks, but if you reveal your database through
timing leaks, the weakest passwords will be vulnerable.

The hardness of the computation can be chosen thus:

- Decide how long the computation should take.  Typically somewhere
  between half a second (convenient) and several seconds (paranoid).

- Try to hash a password with 3 iterations and 100.000 blocks (a
  hundred megabytes).  If it takes too long, reduce that number.  If
  it doesn't take long enough, increase that number.

- If the computation is too short even with all the memory you can
  spare, increase the number of iterations.
-}
argon2i :: Word32
        -> Word32
        -> Maybe SecretKey
        -> Maybe AD
        -> Salt
        -> Password
        -> IO ByteString
argon2i blocks iterations mkey mad (Salt salt) (Password password) =
    -- Deal with block and iteration size validation.

    -- void crypto_argon2i(uint8_t       *hash,      uint32_t hash_size,
    --                     void          *work_area, uint32_t nb_blocks,
    --                     uint32_t       nb_iterations,
    --                     const uint8_t *password,  uint32_t password_size,
    --                     const uint8_t *salt,      uint32_t salt_size,
    --                     const uint8_t *key,       uint32_t key_size,
    --                     const uint8_t *ad,        uint32_t ad_size);

    let areaSize = fromIntegral (blocks * 1024)

     in C.alloca $ \(hashPtr :: Ptr Word8) ->
        C.alloca $ \(hashSizePtr :: Ptr Word32) ->
        C.allocaBytes areaSize $ \(areaPtr :: Ptr ()) ->
        useMaybeAsCStringLen (unsafeSecretKey <$> mkey) $ \(C.castPtr -> keyPtr, keyLen) ->
        useMaybeAsCStringLen (getAD <$> mad) $ \(C.castPtr -> adPtr, adLen) -> do
            [C.block|void {
                crypto_argon2i( $(uint8_t  *hashPtr)
                              , $(uint32_t *hashSizePtr)
                              , $(void     *areaPtr)
                              , $(uint32_t  blocks)
                              , $(uint32_t  iterations)
                              , $bs-ptr:password,    $bs-len:password
                              , $bs-ptr:salt,        $bs-len:salt
                              , $(uint8_t  *keyPtr), $(uint32_t keyLen)
                              , $(uint8_t  *adPtr),  $(uint32_t adLen)
                              );
            }|]

            hashSize <- C.peek hashSizePtr

            BS.packCStringLen (C.castPtr hashPtr, fromIntegral hashSize)

{- $constant_time_comparison
Packaging an easy to use, state of the art, timing immune crypto
library took me over 2 months, full time.  It will all be for naught
if you start leaking information by using standard comparison
functions.

In crypto, we often need to compare secrets together.  A message
authentication code for instance: while the MAC sent over the network
along with a message is public, the true MAC is _secret_.  If the
attacker attempts a forgery, you don't want to tell him "your MAC is
wrong, _and it took me 384 microseconds to figure it out_".  If in the
next attempt it takes you 462 microseconds instead, it gives away the
fact that the attacker just got a few bytes right.  Next thing you
know, you've destroyed integrity.

You need special comparison functions, whose timing do not depend on
the content of the buffers.  They generally work with bit-wise or and
xor.

Monocypher provides 2 functions: `crypto_memcmp()` and
`crypto_zerocmp()`.

    int crypto_memcmp (const uint8_t *p1, const uint8_t *p2, size_t n);
    int crypto_zerocmp(const uint8_t *p , size_t n);

`crypto_memcmp()` returns 0 if it the two memory chunks are the same,
-1 otherwise. `crypto_zerocmp()` returns 0 if all bytes of the memory
chunk are zero, -1 otherwise.  They both run in constant time.  (More
precisely, their timing depends solely on the _length_ of their
inputs.)
-}

class ConstantTimeEq m a where
    constantTimeEq :: a -> a -> m Bool

instance ConstantTimeEq IO MAC where
    constantTimeEq (MAC a) (MAC b)= cryptoCompare a b
    {-# INLINE constantTimeEq #-}

cryptoCompare :: ByteString -> ByteString -> IO Bool
cryptoCompare a b = do
    -- int crypto_memcmp (const uint8_t *p1, const uint8_t *p2, size_t n);

    code <- [C.block|int {
        crypto_memcmp($bs-ptr:a, $bs-ptr:b, $bs-len:a);
    }|]

    pure $! code == 0

cryptoIsZeros :: ByteString -> IO Bool
cryptoIsZeros a = do
    -- int crypto_zerocmp(const uint8_t *p , size_t n);

    code <- [C.block|int {
        crypto_zerocmp($bs-ptr:a, $bs-len:a);
    }|]

    pure $! code == 0

useMaybeAsCStringLen :: Maybe ByteString -> ((Ptr CChar, Word32) -> IO a) -> IO a
useMaybeAsCStringLen mbs f =
    case mbs of
        Nothing -> f (C.nullPtr, 0)
        Just bs -> BS.unsafeUseAsCStringLen bs (f . second fromIntegral)
