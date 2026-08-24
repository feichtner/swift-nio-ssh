/* Shim replacing openssh-portable's includes.h for the vendored
 * sntrup761.c. The only thing the vendored file needs from it is the
 * feature gate. Keep sntrup761.c itself byte-identical to upstream;
 * every adaptation lives in this header, crypto_api.h and shims.c.
 */
#ifndef CNIOSSH_SNTRUP761_INCLUDES_H
#define CNIOSSH_SNTRUP761_INCLUDES_H

#define USE_SNTRUP761X25519 1

/* sntrup761.c zeroes secrets with explicit_bzero, which glibc has but
 * Darwin does not. memset_s is the Darwin equivalent with the same
 * cannot-be-optimised-away guarantee; asking for Annex K here works
 * because this header is included before <string.h>. */
#if defined(__APPLE__)
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#define explicit_bzero(p, n) ((void)memset_s((p), (n), 0, (n)))
#endif

#endif /* CNIOSSH_SNTRUP761_INCLUDES_H */
