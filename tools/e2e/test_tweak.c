/* myJB E2E test tweak (checkm8 + Amethyst smoke test).
 * Pack it with tools/myjb_build.py into a .myjb container; myjb_loader
 * decrypts it and dlopen()s this dylib in matching processes. On load the
 * constructor appends a line to /var/mobile/Library/MyJB/e2e_ok. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

__attribute__((constructor))
static void myjb_e2e_init(void) {
    FILE *f = fopen("/var/mobile/Library/MyJB/e2e_ok", "a");

    if(f == NULL) {
        return;
    }
    fprintf(f, "myjb e2e payload loaded: pid=%d proc=%s time=%ld\n", getpid(), getprogname(), (long)time(NULL));
    fclose(f);
}
