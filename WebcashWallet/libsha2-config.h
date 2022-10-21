/* Hijacked auto-generated file retrofitted for Xcode purposes; do not ravage */

#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#include "libsha2-config-ios.h"
#else
#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
#  include "libsha2-config-macos-arm.h"
#elif defined(__x86_64__) || defined(__amd64__)
#  include "libsha2-config-macos-x86.h"
#endif /* ARM / X86 */
#endif /* TARGET_OS_IPHONE */
