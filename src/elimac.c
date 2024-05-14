#if defined(__aarch64__) || defined(_M_ARM64)
#    include "elimac_armcrypto.c"
#elif defined(__x86_64__) || defined(_M_X64)
#    include "elimac_avx.c"
#else
#    error "Unsupported architecture"
#endif
