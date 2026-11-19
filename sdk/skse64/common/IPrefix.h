#pragma once
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include "common/ITypes.h"

#ifndef ASSERT
#define ASSERT(x) assert(x)
#endif
#ifndef ASSERT_STR
#define ASSERT_STR(x, msg) assert((x) && (msg))
#endif
#ifndef _MESSAGE
#define _MESSAGE(...) ((void)0)
#endif
#ifndef _WARNING
#define _WARNING(...) ((void)0)
#endif
#ifndef _ERROR
#define _ERROR(...) ((void)0)
#endif
