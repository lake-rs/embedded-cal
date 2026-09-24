# embedded-cal: A Guided Tour

This text accompanies novice users of embedded-cal through its components,
following a course of application development that is losely inspired by real-world development.

Familiarity with embedded systems programming and the Rust language is generally assumed,
but instructions should stand alone to the point where general audiences can follow the general track.

---

## Preliminaries: An application

We will assume that you develop a physical message board,
where users can leave each other encrypted messages in NFC tags on objects.
For initial development, you use cell phones as readers,
but eventually, you want to read messages even on a hackable smart watch.

To accommodate the limited storage of NFC tags,
and to avoid re-inventing the wheel in cryptographic protocols,
you pick the [COSE enveloped messages (RFC9052)](https://www.rfc-editor.org/info/rfc9052/) standard.

## Exploring embedded-cal

Of the options around Rust cryptographic tools,
you decide to explore embedded-cal, because it supports algorithm agility well
(not all users of your message board might trust the same set of algorithms),
and because it promises to be usable later on your embedded system.

To get a first impression of how to use it,
you check out its source code and run a first example as described in [the example's documentation](./embedded-cal-examples/README.md):

```console
$ git clone https://github.com/lake-rs/embedded-cal/
$ cd embedded-cal/embedded-cal-examples
$ cargo run --bin demo --features backend-libcrux,log-standalone
[*] Running examples on a Cal of type &mut embedded_cal_libcrux::Extender<embedded_cal_libcrux::standalone::StandaloneConfig>
[*] Computed SHA-256 hash of "hello world" (encoded in ASCII); hash is b9 4d 27 b9 93 4d 3e 08 a5 2e 52 d7 da 7d ab fa c4 84 ef e3 7a 53 80 ee 90 88 f7 ac e2 ef cd e9
[*] Looking to find a matching ECDH curve for Diffie-Hellman key establishment
[*] Agreeing to use curve 1
[*] Public part of our ephemeral key is f7 7c 76 d5 5a fb 0f 1d cc 23 b3 a9 64 06 9a 69 55 83 5a 44 0c fb cf 23 91 6b 1e 6a c7 0a 58 03
[*] Shared secret with that peer is 11 1e 04 aa fb 5f 6c af e6 be 58 a3 48 e7 38 27 00 ef 04 43 e4 3b bf 9a 0e 00 88 81 cd a9 3a 85
[*] Running AEAD test vectors of COSE algorithm 1 (AesGcm128)
[*] Running AEAD test vectors of COSE algorithm 3 (AesGcm256)
[*] All AEAD tests passed.
```

This already mentions some keywords that will be needed later:
performing Diffie-Hellman on elliptic curves (ECDH, needed to encrypt for a specific recipient),
and authenticated encryption with additional data (AEAD, needed to encrypt a full message).

You can have a look at the [example's source code](./embedded-cal-examples/src/lib.rs),
where the ECDH key establishment is performed in `show_ecdh_example()`.

## Integrating with a first application

While in any practical scenario your application would contain countless other components,
let's focus on the cryptographic parts in a mock-up:

```console
$ cargo init my-app
$ cd my-app
$ cargo add embedded-cal rand_core
```

… and add some encryption code to `src/main.rs` (which would be given pieces from the user, and later assembled into a message for the NFC tag).
The steps follow the operations that you would also do in a real COSE implementation
(that is, performing an ECDH key establishment and an AEAD decryption),
but the actual message format is vastly simplified in the interest of focusing on the embedded-cal operations.

```rust
use embedded_cal::{accessor::*, *};
use rand_core::TryCryptoRng;

/// A person in your address book.
struct Friend {
    name: String,
    public_key: Vec<u8>,
    public_key_curve: i16,
    preferred_symmetric_algorithm: i16,
}

fn encrypt<C: Cal + TryCryptoRng>(
    cal: &mut C,
    recipient: &Friend,
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut message = vec![];

    // First we set up an ECDH operation with the known recipient…
    let curve = DhAlgorithmOf::<C>::from_cose_ecdh(recipient.public_key_curve)
        .ok_or("Friend's public key curve is not supported")?;
    let peer_key = cal
        .dh()
        .import_publickey_bytes(curve.clone(), &recipient.public_key)
        .map_err(|_| "Friend's public key is faulty")?;

    // … and as is part of encrypting to an ECDH recipient, we generate a random key and send its
    // public part along with the message.
    let ephemeral = cal.dh().generate(curve);
    let ephemeral_public = cal.dh().public_key(&ephemeral);
    // In COSE, this would really go into the "x" field of the recipient.
    message.extend_from_slice(cal.dh().export_publickey_bytes(&ephemeral_public).as_ref());

    // From those keys, we get an encrytion key…
    let key = cal
        .dh()
        .shared_secret(&ephemeral, &peer_key)
        .expect("both items were constructed on the same curve");
    let key_bytes = cal.dh().raw_secret_bytes(&key);

    // Similar to ECDH, we set up the AEAD steps:
    let aead_alg = AeadAlgorithmOf::<C>::from_cose_number(recipient.preferred_symmetric_algorithm)
        .ok_or("Friend's preferred algorithm is not supported")?;
    let key = cal
        .aead()
        .load_from_keydata(aead_alg.clone(), key_bytes.as_ref());

    // AEAD operations need some nonce, which we construct randomly in this example:
    let mut nonce = Vec::new();
    nonce.resize(aead_alg.nonce_length(), 0);
    cal.try_fill_bytes(&mut nonce)
        .map_err(|_| "Out of random numbers, please restart the universe")?;

    // embedded-cal encrypts in-place, so we place the plaintext in the message but encrypt it
    // there before sending:
    message.extend_from_slice(plaintext);
    // (This would be simpler with a Vec::extend_from_sice_mut() method)
    let bytes_in_message = message.len() - plaintext.len()..message.len();
    let tag = cal.aead().encrypt_in_place(
        &key,
        &nonce,
        &mut message[bytes_in_message],
        // There is no additional data we want to authenticate in our application.
        [0u8; 0].as_slice(),
    );
    // In COSE, the tag is always placed right behind the ciphertext.
    message.extend_from_slice(tag.as_ref());

    Ok(message)
}
```

This already compiles (althought `cargo run` will show you some warnings),
but to do anything, we have to modify the main function to call it.

This comes with an extra step though:
So far, we have just used embedded-cal,
but made no decision on which implementation to use.
Let's go with libcrux:

```console
$ cargo add embedded-cal-libcrux --features standalone
```

Now we can initialize the library, and also put in some sample friend along with a message to be encrypted:

```rust
fn main() {
    let mut cal = embedded_cal_libcrux::Standalone::standalone();

    let bob = Friend {
        name: "Bob".into(),
        // A P-256 key
        public_key: vec![
            0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39,
            0x8c, 0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55,
            0x44, 0x94, 0xbf, 0x63,
        ],
        public_key_curve: 1,
        // AES-GCM 256
        preferred_symmetric_algorithm: 3,
    };

    let message = encrypt(&mut cal, &bob, "Hello Bob!".as_bytes()).unwrap();

    println!("Writing to NFC tag: {:02x?}", message);
}
```

With this, we can get all the data that would be written to our NFC tag:

```console
$ cargo run
Writing to NFC tag: [88, f4, db, c7, 48, 69, af, 80, 16, 10, f5, 1a, 18, ae, a1, a8, a6, 1f, 1b, 87, da, eb, 0b, 93, 34, 39, 12, b3, 4a, cb, b4, 56, a5, 94, 02, d1, 27, 60, 77, e0, 1a, 19, b6, dc, 9e, e2, d0, f9, b1, b9, dd, 82, ec, 58, 18, 04, 58, 57]
```

## Exploring embedded
