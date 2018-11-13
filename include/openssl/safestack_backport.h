/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SAFESTACK_BACKPORT_H
# define HEADER_SAFESTACK_BACKPORT_H

# include <openssl/stack.h>
# include <openssl/e_os2.h>

#ifdef __cplusplus
extern "C" {
#endif

# if OPENSSL_VERSION_NUMBER < 0x10100006L
#  define DEPRECATEDIN_1_0_0(f)=
#  define DEPRECATEDIN_1_1_0(f)=
typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
typedef void (*OPENSSL_sk_freefunc)(void *);
typedef void *(*OPENSSL_sk_copyfunc)(void *);
#  define OPENSSL_STACK _STACK
#  define OPENSSL_sk_value sk_value
#  define OPENSSL_sk_num sk_num
#  define OPENSSL_sk_new sk_new
#  define OPENSSL_sk_new_null sk_new_null
#  define OPENSSL_sk_free sk_free
#  define OPENSSL_sk_zero sk_zero
#  define OPENSSL_sk_delete sk_delete
#  define OPENSSL_sk_delete_ptr sk_delete_ptr
#  define OPENSSL_sk_push sk_push
#  define OPENSSL_sk_unshift sk_unshift
#  define OPENSSL_sk_pop sk_pop
#  define OPENSSL_sk_shift sk_shift
#  define OPENSSL_sk_pop_free sk_pop_free
#  define OPENSSL_sk_insert sk_insert
#  define OPENSSL_sk_set sk_set
#  define OPENSSL_sk_find sk_find
#  define OPENSSL_sk_find_ex sk_find_ex
#  define OPENSSL_sk_sort sk_sort
#  define OPENSSL_sk_is_sorted sk_is_sorted
#  define OPENSSL_sk_dup sk_dup
#  define OPENSSL_sk_deep_copy sk_deep_copy
#  define OPENSSL_sk_set_cmp_func sk_set_cmp_func
# endif

# define STACK_OF(type) struct stack_st_##type

# define SKM_DEFINE_STACK_OF(t1, t2, t3) \
    STACK_OF(t1); \
    typedef int (*sk_##t1##_compfunc)(const t3 * const *a, const t3 *const *b); \
    typedef void (*sk_##t1##_freefunc)(t3 *a); \
    typedef t3 * (*sk_##t1##_copyfunc)(const t3 *a); \
    static ossl_inline int sk_##t1##_num(const STACK_OF(t1) *sk) \
    { \
        return OPENSSL_sk_num((const OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_value(const STACK_OF(t1) *sk, int idx) \
    { \
        return (t2 *)OPENSSL_sk_value((const OPENSSL_STACK *)sk, idx); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new(sk_##t1##_compfunc compare) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new_null(void) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_new_null(); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_new_reserve(sk_##t1##_compfunc compare, int n) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n); \
    } \
    static ossl_inline int sk_##t1##_reserve(STACK_OF(t1) *sk, int n) \
    { \
        return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n); \
    } \
    static ossl_inline void sk_##t1##_free(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_free((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline void sk_##t1##_zero(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_zero((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_delete(STACK_OF(t1) *sk, int i) \
    { \
        return (t2 *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i); \
    } \
    static ossl_inline t2 *sk_##t1##_delete_ptr(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return (t2 *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, \
                                           (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_push(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_push((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_unshift(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline t2 *sk_##t1##_pop(STACK_OF(t1) *sk) \
    { \
        return (t2 *)OPENSSL_sk_pop((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline t2 *sk_##t1##_shift(STACK_OF(t1) *sk) \
    { \
        return (t2 *)OPENSSL_sk_shift((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline void sk_##t1##_pop_free(STACK_OF(t1) *sk, sk_##t1##_freefunc freefunc) \
    { \
        OPENSSL_sk_pop_free((OPENSSL_STACK *)sk, (OPENSSL_sk_freefunc)freefunc); \
    } \
    static ossl_inline int sk_##t1##_insert(STACK_OF(t1) *sk, t2 *ptr, int idx) \
    { \
        return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx); \
    } \
    static ossl_inline t2 *sk_##t1##_set(STACK_OF(t1) *sk, int idx, t2 *ptr) \
    { \
        return (t2 *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_find(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline int sk_##t1##_find_ex(STACK_OF(t1) *sk, t2 *ptr) \
    { \
        return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr); \
    } \
    static ossl_inline void sk_##t1##_sort(STACK_OF(t1) *sk) \
    { \
        OPENSSL_sk_sort((OPENSSL_STACK *)sk); \
    } \
    static ossl_inline int sk_##t1##_is_sorted(const STACK_OF(t1) *sk) \
    { \
        return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk); \
    } \
    static ossl_inline STACK_OF(t1) * sk_##t1##_dup(const STACK_OF(t1) *sk) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk); \
    } \
    static ossl_inline STACK_OF(t1) *sk_##t1##_deep_copy(const STACK_OF(t1) *sk, \
                                                    sk_##t1##_copyfunc copyfunc, \
                                                    sk_##t1##_freefunc freefunc) \
    { \
        return (STACK_OF(t1) *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, \
                                            (OPENSSL_sk_copyfunc)copyfunc, \
                                            (OPENSSL_sk_freefunc)freefunc); \
    } \
    static ossl_inline sk_##t1##_compfunc sk_##t1##_set_cmp_func(STACK_OF(t1) *sk, sk_##t1##_compfunc compare) \
    { \
        return (sk_##t1##_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare); \
    }

# define DEFINE_SPECIAL_STACK_OF(t1, t2) SKM_DEFINE_STACK_OF(t1, t2, t2)
# define DEFINE_STACK_OF(t) SKM_DEFINE_STACK_OF(t, t, t)
# define DEFINE_SPECIAL_STACK_OF_CONST(t1, t2) \
            SKM_DEFINE_STACK_OF(t1, const t2, t2)
# define DEFINE_STACK_OF_CONST(t) SKM_DEFINE_STACK_OF(t, const t, t)

/*-
 * Strings are special: normally an lhash entry will point to a single
 * (somewhat) mutable object. In the case of strings:
 *
 * a) Instead of a single char, there is an array of chars, NUL-terminated.
 * b) The string may have be immutable.
 *
 * So, they need their own declarations. Especially important for
 * type-checking tools, such as Deputy.
 *
 * In practice, however, it appears to be hard to have a const
 * string. For now, I'm settling for dealing with the fact it is a
 * string at all.
 */
typedef char *OPENSSL_STRING;
typedef const char *OPENSSL_CSTRING;

/*-
 * Confusingly, LHASH_OF(STRING) deals with char ** throughout, but
 * STACK_OF(STRING) is really more like STACK_OF(char), only, as mentioned
 * above, instead of a single char each entry is a NUL-terminated array of
 * chars. So, we have to implement STRING specially for STACK_OF. This is
 * dealt with in the autogenerated macros below.
 */
DEFINE_SPECIAL_STACK_OF(OPENSSL_STRING, char)
DEFINE_SPECIAL_STACK_OF_CONST(OPENSSL_CSTRING, char)

/*
 * Similarly, we sometimes use a block of characters, NOT nul-terminated.
 * These should also be distinguished from "normal" stacks.
 */
typedef void *OPENSSL_BLOCK;
DEFINE_SPECIAL_STACK_OF(OPENSSL_BLOCK, void)

# ifdef  __cplusplus
}
# endif
#endif
