/* wc_pkcs11_setup.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _WOLFPKCS11_SETUP_H_
#define _WOLFPKCS11_SETUP_H_

#ifdef __cplusplus
extern "C" {
#endif


/* Necessary Defines and Macros for the OASIS PKCS#11 header files. See
 * pkcs11/pkcs11.h for more details. */


#if defined (_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

#define CK_PTR *

#if defined (_WIN32)
    #define PKCS11_CALLSPEC __cdecl
    #if defined(HAVE_PKCS11_STATIC) || defined(HAVE_PKCS11_STATIC_V3)
        #define PKCS11_DLLIMPORT
    #elif defined(_MSC_VER)
        #define PKCS11_DLLIMPORT __declspec(dllimport)
    #else
        #define PKCS11_DLLIMPORT
    #endif
#else /* _WIN32 */
    #define PKCS11_CALLSPEC
    #define PKCS11_DLLIMPORT
#endif /* _WIN32 */

#define CK_DECLARE_FUNCTION(returnType, name) \
    PKCS11_DLLIMPORT returnType PKCS11_CALLSPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    PKCS11_DLLIMPORT returnType (PKCS11_CALLSPEC *name)

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <wolfssl/wolfcrypt/pkcs11/pkcs11.h>

#if defined (_WIN32)
#pragma pack(pop, cryptoki)
#endif



#ifdef __cplusplus
}
#endif

#endif /* _WOLFPKCS11_SETUP_H_ */
