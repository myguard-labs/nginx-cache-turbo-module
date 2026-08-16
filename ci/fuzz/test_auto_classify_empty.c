/*
 * Deterministic ASan/UBSan smoke for the two zero-length Cookie shapes the
 * auto-classify fuzzer must handle before it can make useful progress.
 */

#include <stdint.h>
#include <stdio.h>

/* Reuse the fuzzer's exact production-slice driver; only main differs. */
#include "fuzz_auto_classify.c"

int
main(void)
{
    static const uint8_t  absent_cookie = 0xff;
    static const uint8_t  present_empty_cookie[] = { 0x00 };

    /* No separator means no Cookie header. A zero-size input is what
     * libFuzzer supplies for its canonical empty seed. */
    if (LLVMFuzzerTestOneInput(&absent_cookie, 0) != 0) {
        return 1;
    }

    /* The separator creates a Cookie node whose value is empty and NULL. */
    if (LLVMFuzzerTestOneInput(present_empty_cookie,
                               sizeof(present_empty_cookie)) != 0)
    {
        return 1;
    }

    puts("OK: auto-classify absent and present-empty Cookie smoke");
    return 0;
}
