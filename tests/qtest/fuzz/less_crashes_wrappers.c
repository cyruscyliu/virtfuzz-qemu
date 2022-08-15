/*
 * Type-Aware Virtual-Device Fuzzing Less Crashes Wrapper
 *
 * Copyright Red Hat Inc., 2020
 *
 * Authors:
 *  Qiang Liu <cyruscyliu@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#define WRAP(RET_TYPE, NAME_AND_ARGS)\
    RET_TYPE __wrap_##NAME_AND_ARGS;\
    RET_TYPE __real_##NAME_AND_ARGS;

WRAP(void     , abort())

void __wrap_abort()
{
#ifdef VIDEZZO_LESS_CRASHES
    return;
#else
    return __real_abort();
#endif
}
