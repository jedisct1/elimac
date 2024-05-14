#if defined(__aarch64__) || defined(_M_ARM64)
#    include "elimac_armcrypto.c"
#elif defined(__x86_64__) || defined(_M_X64)
#    if defined(__AVX512F__) && defined(__VAES__)
#        include "elimac_avx512.c"
#    elif defined(__AVX2__) && defined(__VAES__)
#        include "elimac_avx2.c"
#    else
#        include "elimac_avx.c"
#    endif
#else
#    error "Unsupported architecture"
#endif
