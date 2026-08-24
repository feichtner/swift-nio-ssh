# CNIOSSHSNTRUP761

The Streamlined NTRU Prime 761 KEM, vendored for the
`sntrup761x25519-sha512` hybrid post-quantum SSH key exchange.

`sntrup761.c` is copied **byte-identical** from openssh-portable
(`sntrup761.c` at upstream commit `0ef0f5a83983`, itself generated from
SUPERCOP). It is public domain, by Daniel J. Bernstein, Chitchanok
Chuengsatiansup, Tanja Lange and Christine van Vredendaal. Do not edit
it; refresh it by re-copying from upstream and re-running the tests.

Everything the file expects from its OpenSSH host is supplied here
instead:

- `include/includes.h`, `include/crypto_api.h` — minimal shims for the
  two headers it includes. `crypto_api.h` is also this target's public
  interface (the three `crypto_kem_sntrup761_*` entry points, plus
  `crypto_hash_sha512` so tests can pin it to FIPS 180-4 vectors).
- `shims.c` — the three `*_optblocker` volatiles (upstream defines them
  in `kexsntrup761x25519.c`), `randombytes` as a chunked `getentropy`
  loop, and a plain FIPS 180-4 SHA-512 (upstream maps it to libcrypto,
  which this package does not depend on).
