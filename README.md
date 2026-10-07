# age encrypt for YubiKey PIV

A single HTML file that encrypts secrets with [age](https://age-encryption.org),
to ordinary `age1...` recipients and to `age1yubikey1...` recipients from
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey).

It only encrypts. It has no way to decrypt, makes no network requests, stores
nothing, and has no dependencies: `index.html` is one `<style>` block and one
`<script>` block of about 300 lines that you can read in one sitting.

## Why

For keeping small secrets (a bank password, recovery codes) where each one is
encrypted once and left alone until it is needed. There is no vault file to
decrypt, edit and re-encrypt. Each secret is its own `.age` file, and replacing
a secret means encrypting a new file over the old one.

Decryption happens outside the browser, in a terminal, with the YubiKey plugged
in.

## Use

1. Open `index.html` from disk. A private window with no extensions is best.
2. Add the recipients: paste them in, one per line, or load a recipients file.
   None are built in. Lines starting with `#` are comments. The line
   under the box shows each YubiKey's tag, which matches the name of its
   identity file (`age-yubikey-identity-9f0be82b.txt` has tag `9f0be82b`).
3. Type a label and the secret, or choose a file to encrypt byte for byte.
4. Press Encrypt, then Download or Copy. The file is named `LABEL.age`. In
   Chrome and Edge, Download asks where to save it. Other browsers use their
   normal download folder.

To decrypt:

    age -d -i age-yubikey-identity-XXXXXXXX.txt LABEL.age

The label is not encrypted. It is the file name, so anyone who can see the
files can see that `bank-example.age` exists.

Typed secrets are padded with trailing newlines to a multiple of 256 bytes so
the file size does not give away the length. Files are never padded.

## PIV versus WebAuthn PRF

There are two ways to encrypt with a YubiKey. This page does the first.

**PIV (age-plugin-yubikey), supported.** The YubiKey holds a P-256 private key
in a PIV slot. It was generated on the device and PIV has no command to export
it, so it has never left the device. The `age1yubikey1...` recipient is only the
public key.

- Encrypting needs the public key and nothing else: no YubiKey, no PIN, no
  touch.
- Decrypting needs the YubiKey, its PIN and a touch, and runs through `age` and
  `age-plugin-yubikey` in a terminal. Browsers cannot talk to PIV.
- A page that encrypts this way, even a tampered one, can see a secret while
  you type it but cannot read back the ones already encrypted.

**WebAuthn PRF (FIDO2 hmac-secret), not supported.** The browser asks the
YubiKey to derive a secret key and hands that key to the page.

- It is one shared key, so the YubiKey must be present and touched to encrypt
  as well as to decrypt.
- The credential stays on the device, but the derived key is given to the page.
  Any page that can encrypt can also decrypt.

PRF is more convenient because everything happens in the browser. That is also
the reason it is left out: here the browser never holds anything that can
decrypt.

## What to trust, and how to check it

- **The file.** An audit only covers the exact file that was audited. Record
  its hash and check it before use:

      sha256sum index.html

- **The network.** The page's Content-Security-Policy is `default-src 'none'`
  plus one hash each for the style and script blocks, so the browser refuses
  every request and any script other than the one in the file. A CSP does not
  stop a script from navigating the page somewhere else, so the script contains
  no navigation, and the tests check for that. For a real air gap, turn the
  network off.
- **Browser extensions.** They sit outside the CSP and can read the page. Use a
  private window or a clean profile.
- **The recipient list.** If someone changes it, you encrypt to them. Check the
  tags before encrypting.
- **Forgery.** age does not sign anything. Anyone with your public recipients
  can make a file that decrypts correctly. If that matters, keep the `.age`
  files in a git repository with signed commits.

## Auditing the file with an LLM

The page is small enough to hand to a language model in one go. This is a
second pair of eyes, not a proof: models miss things, so ask more than one, and
read the script yourself if you can.

1. Get the file from somewhere you trust and note its hash: `sha256sum index.html`.
2. Give the model the file itself. Attach `index.html`, or copy it with
   `pbcopy < index.html` (macOS) or `xclip -sel clip < index.html` (Linux). Do
   not let a web page hand over its own source: a tampered page would hand over
   a clean copy.
3. Paste the prompt below.
4. The answer only covers the file with that hash. Any edit means a new audit.

```
This is a single HTML file that claims to encrypt secrets with the age format
(age-encryption.org/v1) to X25519 recipients and to age-plugin-yubikey (PIV,
P-256) recipients. It claims it cannot decrypt, makes no network requests,
stores nothing, and loads no outside code. Audit it against those claims.
Quote the exact line for every finding, and say "none found" where that is the
answer. Do not summarise what the code is supposed to do; report what it does.

1. Data leaving the page. List every way data could leave: network APIs,
   navigation, links, forms, images or other resource loads, storage, cookies,
   messaging, workers, the clipboard, file writes, downloads. For each one found,
   say what data it carries and what user action triggers it.
2. Content-Security-Policy. State what the policy allows and blocks, and
   whether the page relies on anything the policy does not cover.
3. Outside or dynamic code. Any external scripts, styles, fonts or frames? Any
   eval, Function constructor, dynamic import, or HTML built from strings?
4. The secret. Trace the typed secret and the chosen file from input to
   output. Is the plaintext, the file key, or any ephemeral private key kept
   anywhere after encryption, or sent anywhere other than into the cipher?
5. Decryption. Is there any code that could decrypt an age file or recover a
   file key?
6. Randomness. Where do the file key, the payload nonce and the ephemeral keys
   come from? Is anything reused across recipients or across files that should
   not be?
7. Cryptography. Check against the age v1 spec and RFC 8439: the X25519
   stanza, the piv-p256 stanza used by age-plugin-yubikey (tag, ephemeral
   share, HKDF salt and info, zero nonce), the header MAC, the payload key, the
   64 KiB chunking and chunk nonces including the last-chunk flag, and the
   hand-written ChaCha20, Poly1305, bech32 decoder and P-256 decompression.
8. Anything else. Obfuscated code, unused code, odd constants, or behaviour
   that does not serve the stated purpose.

Finish with a one-paragraph verdict and a list of anything you could not verify.
```

What a clean answer looks like: the only ways out are the Copy button (the
encrypted text to the clipboard) and the Download button (the encrypted text to
a file you choose or to the downloads folder); nothing is stored; there is no
decryption code; and all randomness comes from `crypto.getRandomValues` or
WebCrypto key generation, fresh for every file and every recipient.

## What is hand-written

WebCrypto does P-256, X25519, HKDF, HMAC, SHA-256 and random numbers. The page
adds ChaCha20-Poly1305, a bech32 decoder, P-256 point decompression and the age
file format.

Not supported: post-quantum recipients, passphrases, SSH keys, other plugins.

## Tests

    bun install
    bun test

Needs `chromium` on the PATH. The tests load `index.html` from disk in headless
Chromium, with its real CSP, and drive it over the DevTools protocol. None of
the page's code runs in bun. They check:

- ChaCha20 and Poly1305 against the RFC 8439 vectors, and the combined cipher,
  bech32 and point decompression against the noble and bech32 packages
- that [typage](https://github.com/FiloSottile/typage) decrypts what the page
  encrypts, for both recipient types and across the 64 KiB chunk boundary
- the form, the file inputs and the light/dark switch
- that the browser blocks a network request
- that the script contains no network, storage or dynamic-code API names

The YubiKey side in the tests is a software stand-in. Decrypting the page's
output with a real YubiKey has not been confirmed yet.

## Editing

The CSP holds a hash of each inline block, so any change to the style or script
needs a reseal, or the browser will refuse to run it:

    bun seal.ts index.html                  # after editing the script or markup
    bun seal.ts index.html styles/best.css  # after editing the style

`seal.ts` prints the new SHA-256 of the file.

## License

MIT. See [LICENSE](LICENSE).
