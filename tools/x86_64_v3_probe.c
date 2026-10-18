#include <stdio.h>

int main(void) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    if (__builtin_cpu_supports("x86-64-v3")) return 0;
    (void)fprintf(stderr, "host CPU does not support x86-64-v3\n");
    return 1;
#else
    (void)fprintf(stderr, "x86-64-v3 probe requires GCC or Clang on x86-64\n");
    return 1;
#endif
}
