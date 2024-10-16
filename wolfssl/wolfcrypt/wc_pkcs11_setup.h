/* wc_pkcs11_setup.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
    #if defined(HAVE_PKCS11_STATIC)
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


/* PQC - Post-Quantum Cryptography Extensions */

/* vendor defined attributes */

#define CKA_ENCAPSULATE (CKA_VENDOR_DEFINED | 0x00000401UL)
#define CKA_DECAPSULATE (CKA_VENDOR_DEFINED | 0x00000402UL)

#define CKA_PARAMETER_SET (CKA_VENDOR_DEFINED | 0x00000501UL)

/* vendor defined mechanisms */
#define CKM_ML_KEM_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0008001UL)
#define CKM_ML_DSA_KEY_PAIR_GEN (CKM_VENDOR_DEFINED | 0x0008002UL)

#define CKM_ML_KEM (CKM_VENDOR_DEFINED | 0x0008003UL)
#define CKM_ML_DSA (CKM_VENDOR_DEFINED | 0x0008004UL)

#define CKM_SHAKE128 (CKM_VENDOR_DEFINED | 0x0008005UL)
#define CKM_SHAKE256 (CKM_VENDOR_DEFINED | 0x0008006UL)

/* vendor defined keytypes */
#define CKK_ML_DSA (CKK_VENDOR_DEFINED | 0x0004001UL)
#define CKK_ML_KEM (CKK_VENDOR_DEFINED | 0x0004002UL)

/* parameter set types */

typedef CK_ULONG CK_ML_DSA_PARAMETER_SET_TYPE;

typedef CK_ML_DSA_PARAMETER_SET_TYPE CK_PTR CK_ML_DSA_PARAMETER_SET_TYPE_PTR;

#define CKP_ML_DSA_44          0x00000001UL
#define CKP_ML_DSA_65          0x00000002UL
#define CKP_ML_DSA_87          0x00000003UL

/*
 * CK_ML_DSA_PARAMS provides parameters for ML-DSA sign and verify
 * operations.
 *
 * The `phFlag` is a flag to indicate if the pre-hash is used. If `phFlag` is
 * set to `CK_TRUE`, the `hash` parameter is used as pre-hash algorithm. If
 * set to `CK_FALSE`, the `hash` parameter is ignored.
 *
 * Allowed mechanisms for `hash` are:
 * - CKM_SHA256
 * - CKM_SHA384
 * - CKM_SHA512
 * - CKM_SHA512_256  (defined in `pkcs11t.h` V3.1)
 * - CKM_SHA3_256    (defined in `pkcs11t.h` V3.1)
 * - CKM_SHA3_384    (defined in `pkcs11t.h` V3.1)
 * - CKM_SHA3_512    (defined in `pkcs11t.h` V3.1)
 * - CKM_SHAKE128    (vendor defined above, since not yet in PKCS#11)
 * - CKM_SHAKE256    (vendor defined above, since not yet in PKCS#11)
 *
 * The `ulContextDataLen` and `pContextData` parameters are used to provide
 * additional context data for the signature operation. The maximum length of
 * the context data is 255 bytes. If no context data is used for the operation,
 * `ulContextDataLen` must be set to 0 and `pContextData` must be set to `NULL`.
 *
 * When no CK_ML_DSA_PARAMS structure is set in `C_SignInit` or `C_VerifyInit`
 * (`pMechanism->ulParameterLen = 0` and `pMechanism->pParameter = NULL`), then
 * the operation is performed without pre-hash and without context data.
 */
typedef struct CK_ML_DSA_PARAMS {
    CK_BBOOL            phFlag;
    CK_MECHANISM_TYPE   hash;
    CK_ULONG            ulContextDataLen;
    CK_BYTE_PTR         pContextData;
} CK_ML_DSA_PARAMS;

typedef CK_ML_DSA_PARAMS* CK_ML_DSA_PARAMS_PTR;


typedef CK_ULONG CK_ML_KEM_PARAMETER_SET_TYPE;

typedef CK_ML_KEM_PARAMETER_SET_TYPE CK_PTR CK_ML_KEM_PARAMETER_SET_TYPE_PTR;

#define CKP_ML_KEM_512          0x00000021UL
#define CKP_ML_KEM_768          0x00000022UL
#define CKP_ML_KEM_1024         0x00000023UL

/*
 * CK_ML_KEM_PARAMS provides the parameters to the
 * CKM_ML_KEM mechanisms, where each party contributes one key pair.
 */
typedef struct CK_ML_KEM_PARAMS {
  CK_BYTE_PTR           pPublicKey;
  CK_ULONG              ulPublicKeyLen;
} CK_ML_KEM_PARAMS;

typedef CK_ML_KEM_PARAMS CK_PTR CK_ML_KEM_PARAMS_PTR;


/* vendor defined flags */
#define CKF_ENCAPSULATE            (CKF_EXTENSION | 0x00000001UL)
#define CKF_DECAPSULATE            (CKF_EXTENSION | 0x00000002UL)


#ifdef __cplusplus
}
#endif

#endif /* _WOLFPKCS11_SETUP_H_ */
