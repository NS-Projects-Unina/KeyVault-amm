#include "service_utility.h"
#include <stdlib.h> // Per srand, rand
#include <time.h>   // Per time

void generate_random_otp(char *out, size_t len) {
    const char charset[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    static int seeded = 0;
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }

    for (size_t i = 0; i < len - 1; i++) {
        out[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    out[len - 1] = '\0';
}