/* Lambda's provided.al2023 runtime has glibc 2.34. aws-lc, compiled on a newer glibc, references the C23 variants
 * __isoc23_strtol and __isoc23_sscanf (glibc 2.38). They differ from strtol and sscanf only in accepting a
 * "0b" binary prefix, which nothing here relies on. This file (compiled as C17, so strtol and sscanf are the
 * classic ones) defines them in terms of the classic functions, so the binary runs on glibc 2.34. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

long __isoc23_strtol(const char *s, char **end, int base) { return strtol(s, end, base); }

int __isoc23_sscanf(const char *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsscanf(s, fmt, ap);
    va_end(ap);
    return r;
}
