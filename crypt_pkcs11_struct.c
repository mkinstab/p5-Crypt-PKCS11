/*
 * Copyright (c) 2015 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2015 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "crypt_pkcs11_struct.h"

#include <stdlib.h>
#include <string.h>

#ifdef TEST_DEVEL_COVER
int __test_devel_cover_calloc_always_fail = 0;
#define myNewxz(a,b,c) if (__test_devel_cover_calloc_always_fail) { a = 0; } else { Newxz(a, b, c); }
#define __croak(x) return 0
/* uncoverable begin */
int crypt_pkcs11_struct_xs_test_devel_cover(void) {
    {
        Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT);
        if (!object) { return __LINE__; };
        myNewxz(object->private.pIVClient, 1, char);
        if (!object->private.pIVClient) { return __LINE__; }
        myNewxz(object->private.pIVServer, 1, char);
        if (!object->private.pIVServer) { return __LINE__; }
        crypt_pkcs11_ck_ssl3_key_mat_out_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS);
        if (!object) { return __LINE__; };
        myNewxz(object->pReturnedKeyMaterial.pIVClient, 1, char);
        if (!object->pReturnedKeyMaterial.pIVClient) { return __LINE__; }
        myNewxz(object->pReturnedKeyMaterial.pIVServer, 1, char);
        if (!object->pReturnedKeyMaterial.pIVServer) { return __LINE__; }
        crypt_pkcs11_ck_ssl3_key_mat_params_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT);
        if (!object) { return __LINE__; };
        myNewxz(object->private.pIV, 1, char);
        if (!object->private.pIV) { return __LINE__; }
        crypt_pkcs11_ck_wtls_key_mat_out_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object = 0;
        myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS);
        if (!object) { return __LINE__; };
        myNewxz(object->pReturnedKeyMaterial.pIV, 1, char);
        if (!object->pReturnedKeyMaterial.pIV) { return __LINE__; }
        crypt_pkcs11_ck_wtls_key_mat_params_DESTROY(object);
    }
    return 0;
}
/* uncoverable end */
#else
#define myNewxz Newxz
#define __croak(x) croak(x)
#endif

extern int crypt_pkcs11_xs_SvUOK(SV* sv);

Crypt__PKCS11__CK_VERSION* crypt_pkcs11_ck_version_new(const char* class) {
    Crypt__PKCS11__CK_VERSION* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_VERSION);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_version_toBytes(Crypt__PKCS11__CK_VERSION* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_VERSION));
}

CK_RV crypt_pkcs11_ck_version_fromBytes(Crypt__PKCS11__CK_VERSION* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_VERSION))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_version_DESTROY(Crypt__PKCS11__CK_VERSION* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_version_get_major(Crypt__PKCS11__CK_VERSION* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.major);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_version_set_major(Crypt__PKCS11__CK_VERSION* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.major = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_version_get_minor(Crypt__PKCS11__CK_VERSION* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.minor);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_version_set_minor(Crypt__PKCS11__CK_VERSION* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.minor = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_MECHANISM* crypt_pkcs11_ck_mechanism_new(const char* class) {
    Crypt__PKCS11__CK_MECHANISM* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_MECHANISM);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_mechanism_toBytes(Crypt__PKCS11__CK_MECHANISM* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_MECHANISM));
}

CK_RV crypt_pkcs11_ck_mechanism_fromBytes(Crypt__PKCS11__CK_MECHANISM* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_MECHANISM))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pParameter) {
        Safefree(object->private.pParameter);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pParameter) {
        CK_BYTE_PTR pParameter = 0;
        myNewxz(pParameter, object->private.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pParameter, pParameter, object->private.ulParameterLen, CK_BYTE);
        object->private.pParameter = pParameter;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_mechanism_DESTROY(Crypt__PKCS11__CK_MECHANISM* object) {
    if (object) {
        if (object->private.pParameter) {
            Safefree(object->private.pParameter);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_mechanism_get_mechanism(Crypt__PKCS11__CK_MECHANISM* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.mechanism);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_mechanism_set_mechanism(Crypt__PKCS11__CK_MECHANISM* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.mechanism = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_mechanism_get_pParameter(Crypt__PKCS11__CK_MECHANISM* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pParameter, object->private.ulParameterLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_mechanism_set_pParameter(Crypt__PKCS11__CK_MECHANISM* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pParameter) {
            Safefree(object->private.pParameter);
            object->private.pParameter = 0;
            object->private.ulParameterLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pParameter) {
        Safefree(object->private.pParameter);
    }
    object->private.pParameter = n;
    object->private.ulParameterLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* crypt_pkcs11_ck_rsa_pkcs_oaep_params_new(const char* class) {
    Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rsa_pkcs_oaep_params_toBytes(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RSA_PKCS_OAEP_PARAMS));
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_fromBytes(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSourceData) {
        Safefree(object->private.pSourceData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSourceData) {
        CK_BYTE_PTR pSourceData = 0;
        myNewxz(pSourceData, object->private.ulSourceDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSourceData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSourceData, pSourceData, object->private.ulSourceDataLen, CK_BYTE);
        object->private.pSourceData = pSourceData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_rsa_pkcs_oaep_params_DESTROY(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object) {
    if (object) {
        if (object->private.pSourceData) {
            Safefree(object->private.pSourceData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hashAlg);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hashAlg = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_mgf(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.mgf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_mgf(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.mgf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_source(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.source);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_source(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.source = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_pSourceData(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSourceData, object->private.ulSourceDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_pSourceData(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSourceData) {
            Safefree(object->private.pSourceData);
            object->private.pSourceData = 0;
            object->private.ulSourceDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSourceData) {
        Safefree(object->private.pSourceData);
    }
    object->private.pSourceData = n;
    object->private.ulSourceDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* crypt_pkcs11_ck_rsa_pkcs_pss_params_new(const char* class) {
    Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rsa_pkcs_pss_params_toBytes(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RSA_PKCS_PSS_PARAMS));
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_fromBytes(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RSA_PKCS_PSS_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_rsa_pkcs_pss_params_DESTROY(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_get_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hashAlg);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_set_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hashAlg = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_get_mgf(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.mgf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_set_mgf(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.mgf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_get_sLen(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.sLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_set_sLen(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.sLen = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* crypt_pkcs11_ck_ecdh1_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ecdh1_derive_params_toBytes(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_ECDH1_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_fromBytes(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_ECDH1_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSharedData) {
        Safefree(object->private.pSharedData);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSharedData) {
        CK_BYTE_PTR pSharedData = 0;
        myNewxz(pSharedData, object->private.ulSharedDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSharedData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSharedData, pSharedData, object->private.ulSharedDataLen, CK_BYTE);
        object->private.pSharedData = pSharedData;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ecdh1_derive_params_DESTROY(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pSharedData) {
            Safefree(object->private.pSharedData);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_get_kdf(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.kdf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_kdf(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.kdf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_get_pSharedData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSharedData, object->private.ulSharedDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSharedData) {
            Safefree(object->private.pSharedData);
            object->private.pSharedData = 0;
            object->private.ulSharedDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSharedData) {
        Safefree(object->private.pSharedData);
    }
    object->private.pSharedData = n;
    object->private.ulSharedDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_get_pPublicData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* crypt_pkcs11_ck_ecdh2_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ecdh2_derive_params_toBytes(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_ECDH2_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_fromBytes(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_ECDH2_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSharedData) {
        Safefree(object->private.pSharedData);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSharedData) {
        CK_BYTE_PTR pSharedData = 0;
        myNewxz(pSharedData, object->private.ulSharedDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSharedData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSharedData, pSharedData, object->private.ulSharedDataLen, CK_BYTE);
        object->private.pSharedData = pSharedData;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = 0;
        myNewxz(pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData2, pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ecdh2_derive_params_DESTROY(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pSharedData) {
            Safefree(object->private.pSharedData);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_kdf(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.kdf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_kdf(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.kdf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_pSharedData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSharedData, object->private.ulSharedDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSharedData) {
            Safefree(object->private.pSharedData);
            object->private.pSharedData = 0;
            object->private.ulSharedDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSharedData) {
        Safefree(object->private.pSharedData);
    }
    object->private.pSharedData = n;
    object->private.ulSharedDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_hPrivateData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hPrivateData);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_hPrivateData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hPrivateData = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
            object->private.pPublicData2 = 0;
            object->private.ulPublicDataLen2 = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    object->private.pPublicData2 = n;
    object->private.ulPublicDataLen2 = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* crypt_pkcs11_ck_ecmqv_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ecmqv_derive_params_toBytes(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_ECMQV_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_fromBytes(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_ECMQV_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSharedData) {
        Safefree(object->private.pSharedData);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSharedData) {
        CK_BYTE_PTR pSharedData = 0;
        myNewxz(pSharedData, object->private.ulSharedDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSharedData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSharedData, pSharedData, object->private.ulSharedDataLen, CK_BYTE);
        object->private.pSharedData = pSharedData;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = 0;
        myNewxz(pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData2, pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ecmqv_derive_params_DESTROY(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pSharedData) {
            Safefree(object->private.pSharedData);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_kdf(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.kdf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_kdf(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.kdf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_pSharedData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSharedData, object->private.ulSharedDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSharedData) {
            Safefree(object->private.pSharedData);
            object->private.pSharedData = 0;
            object->private.ulSharedDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSharedData) {
        Safefree(object->private.pSharedData);
    }
    object->private.pSharedData = n;
    object->private.ulSharedDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_hPrivateData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hPrivateData);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_hPrivateData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hPrivateData = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
            object->private.pPublicData2 = 0;
            object->private.ulPublicDataLen2 = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    object->private.pPublicData2 = n;
    object->private.ulPublicDataLen2 = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_publicKey(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.publicKey);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_publicKey(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.publicKey = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_dh1_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_x9_42_dh1_derive_params_toBytes(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_X9_42_DH1_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_fromBytes(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_X9_42_DH1_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pOtherInfo) {
        Safefree(object->private.pOtherInfo);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pOtherInfo) {
        CK_BYTE_PTR pOtherInfo = 0;
        myNewxz(pOtherInfo, object->private.ulOtherInfoLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOtherInfo) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOtherInfo, pOtherInfo, object->private.ulOtherInfoLen, CK_BYTE);
        object->private.pOtherInfo = pOtherInfo;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_x9_42_dh1_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pOtherInfo) {
            Safefree(object->private.pOtherInfo);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_get_kdf(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.kdf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_kdf(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.kdf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOtherInfo, object->private.ulOtherInfoLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOtherInfo) {
            Safefree(object->private.pOtherInfo);
            object->private.pOtherInfo = 0;
            object->private.ulOtherInfoLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOtherInfo) {
        Safefree(object->private.pOtherInfo);
    }
    object->private.pOtherInfo = n;
    object->private.ulOtherInfoLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pPublicData(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_dh2_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_x9_42_dh2_derive_params_toBytes(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_X9_42_DH2_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_fromBytes(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_X9_42_DH2_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pOtherInfo) {
        Safefree(object->private.pOtherInfo);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pOtherInfo) {
        CK_BYTE_PTR pOtherInfo = 0;
        myNewxz(pOtherInfo, object->private.ulOtherInfoLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOtherInfo) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOtherInfo, pOtherInfo, object->private.ulOtherInfoLen, CK_BYTE);
        object->private.pOtherInfo = pOtherInfo;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = 0;
        myNewxz(pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData2, pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_x9_42_dh2_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pOtherInfo) {
            Safefree(object->private.pOtherInfo);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_kdf(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.kdf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_kdf(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.kdf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOtherInfo, object->private.ulOtherInfoLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOtherInfo) {
            Safefree(object->private.pOtherInfo);
            object->private.pOtherInfo = 0;
            object->private.ulOtherInfoLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOtherInfo) {
        Safefree(object->private.pOtherInfo);
    }
    object->private.pOtherInfo = n;
    object->private.ulOtherInfoLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_hPrivateData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hPrivateData);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_hPrivateData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hPrivateData = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
            object->private.pPublicData2 = 0;
            object->private.ulPublicDataLen2 = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    object->private.pPublicData2 = n;
    object->private.ulPublicDataLen2 = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_mqv_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_x9_42_mqv_derive_params_toBytes(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_X9_42_MQV_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_fromBytes(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_X9_42_MQV_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pOtherInfo) {
        Safefree(object->private.pOtherInfo);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pOtherInfo) {
        CK_BYTE_PTR pOtherInfo = 0;
        myNewxz(pOtherInfo, object->private.ulOtherInfoLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOtherInfo) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOtherInfo, pOtherInfo, object->private.ulOtherInfoLen, CK_BYTE);
        object->private.pOtherInfo = pOtherInfo;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = 0;
        myNewxz(pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData2, pPublicData2, object->private.ulPublicDataLen2, CK_BYTE);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_x9_42_mqv_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pOtherInfo) {
            Safefree(object->private.pOtherInfo);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_kdf(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.kdf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_kdf(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.kdf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pOtherInfo(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOtherInfo, object->private.ulOtherInfoLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOtherInfo) {
            Safefree(object->private.pOtherInfo);
            object->private.pOtherInfo = 0;
            object->private.ulOtherInfoLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOtherInfo) {
        Safefree(object->private.pOtherInfo);
    }
    object->private.pOtherInfo = n;
    object->private.ulOtherInfoLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_hPrivateData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hPrivateData);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_hPrivateData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hPrivateData = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData2) {
            Safefree(object->private.pPublicData2);
            object->private.pPublicData2 = 0;
            object->private.ulPublicDataLen2 = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData2) {
        Safefree(object->private.pPublicData2);
    }
    object->private.pPublicData2 = n;
    object->private.ulPublicDataLen2 = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_publicKey(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.publicKey);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_publicKey(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.publicKey = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* crypt_pkcs11_ck_kea_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_KEA_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_kea_derive_params_toBytes(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_KEA_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_kea_derive_params_fromBytes(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_KEA_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pRandomA) {
        Safefree(object->private.pRandomA);
    }
    if (object->private.pRandomB) {
        Safefree(object->private.pRandomB);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pRandomA) {
        CK_BYTE_PTR pRandomA = 0;
        myNewxz(pRandomA, object->private.ulRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pRandomA, pRandomA, object->private.ulRandomLen, CK_BYTE);
        object->private.pRandomA = pRandomA;
    }
    if (object->private.pRandomB) {
        CK_BYTE_PTR pRandomB = 0;
        myNewxz(pRandomB, object->private.ulRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pRandomB) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pRandomB, pRandomB, object->private.ulRandomLen, CK_BYTE);
        object->private.pRandomB = pRandomB;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_kea_derive_params_DESTROY(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pRandomA) {
            Safefree(object->private.pRandomA);
        }
        if (object->private.pRandomB) {
            Safefree(object->private.pRandomB);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_isSender(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.isSender);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_isSender(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (SvUV(sv)) {
        object->private.isSender = CK_TRUE;
    }
    else {
        object->private.isSender = CK_FALSE;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_pRandomA(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pRandomA, object->private.ulRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pRandomA(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pRandomA) {
            Safefree(object->private.pRandomA);
            object->private.pRandomA = 0;
            object->private.ulRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pRandomA) {
        Safefree(object->private.pRandomA);
    }
    object->private.pRandomA = n;
    object->private.ulRandomLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_pRandomB(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pRandomB, object->private.ulRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pRandomB(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pRandomB) {
            Safefree(object->private.pRandomB);
            object->private.pRandomB = 0;
            object->private.ulRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pRandomB) {
        Safefree(object->private.pRandomB);
    }
    object->private.pRandomB = n;
    object->private.ulRandomLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_pPublicData(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pPublicData(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RC2_CBC_PARAMS* crypt_pkcs11_ck_rc2_cbc_params_new(const char* class) {
    Crypt__PKCS11__CK_RC2_CBC_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RC2_CBC_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc2_cbc_params_toBytes(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RC2_CBC_PARAMS));
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_fromBytes(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RC2_CBC_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc2_cbc_params_DESTROY(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_get_ulEffectiveBits(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulEffectiveBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_set_ulEffectiveBits(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulEffectiveBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_get_iv(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.iv, 8 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_set_iv(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.iv, 8, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (8 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.iv, 8, CK_BYTE);

    return CKR_OK;
}

Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* crypt_pkcs11_ck_rc2_mac_general_params_new(const char* class) {
    Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc2_mac_general_params_toBytes(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RC2_MAC_GENERAL_PARAMS));
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_fromBytes(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RC2_MAC_GENERAL_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc2_mac_general_params_DESTROY(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_get_ulEffectiveBits(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulEffectiveBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_set_ulEffectiveBits(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulEffectiveBits = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_PARAMS* crypt_pkcs11_ck_rc5_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RC5_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc5_params_toBytes(Crypt__PKCS11__CK_RC5_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RC5_PARAMS));
}

CK_RV crypt_pkcs11_ck_rc5_params_fromBytes(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RC5_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc5_params_DESTROY(Crypt__PKCS11__CK_RC5_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rc5_params_get_ulWordsize(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulWordsize);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_params_set_ulWordsize(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulWordsize = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_params_get_ulRounds(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulRounds);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_params_set_ulRounds(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulRounds = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_CBC_PARAMS* crypt_pkcs11_ck_rc5_cbc_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_CBC_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RC5_CBC_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc5_cbc_params_toBytes(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RC5_CBC_PARAMS));
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_fromBytes(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RC5_CBC_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pIv) {
        Safefree(object->private.pIv);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pIv) {
        CK_BYTE_PTR pIv = 0;
        myNewxz(pIv, object->private.ulIvLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIv) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pIv, pIv, object->private.ulIvLen, CK_BYTE);
        object->private.pIv = pIv;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_rc5_cbc_params_DESTROY(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object) {
    if (object) {
        if (object->private.pIv) {
            Safefree(object->private.pIv);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_get_ulWordsize(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulWordsize);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_ulWordsize(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulWordsize = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_get_ulRounds(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulRounds);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_ulRounds(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulRounds = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_get_pIv(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pIv, object->private.ulIvLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_pIv(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pIv) {
            Safefree(object->private.pIv);
            object->private.pIv = 0;
            object->private.ulIvLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pIv) {
        Safefree(object->private.pIv);
    }
    object->private.pIv = n;
    object->private.ulIvLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* crypt_pkcs11_ck_rc5_mac_general_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc5_mac_general_params_toBytes(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_RC5_MAC_GENERAL_PARAMS));
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_fromBytes(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_RC5_MAC_GENERAL_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc5_mac_general_params_DESTROY(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_get_ulWordsize(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulWordsize);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_set_ulWordsize(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulWordsize = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_get_ulRounds(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulRounds);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_set_ulRounds(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulRounds = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_des_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_des_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS));
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_fromBytes(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pData) {
        CK_BYTE_PTR pData = 0;
        myNewxz(pData, object->private.length, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pData, pData, object->private.length, CK_BYTE);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_des_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            Safefree(object->private.pData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.iv, 8 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.iv, 8, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (8 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.iv, 8, CK_BYTE);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pData, object->private.length * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pData) {
            Safefree(object->private.pData);
            object->private.pData = 0;
            object->private.length = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_aes_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS));
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_fromBytes(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pData) {
        CK_BYTE_PTR pData = 0;
        myNewxz(pData, object->private.length, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pData, pData, object->private.length, CK_BYTE);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aes_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            Safefree(object->private.pData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.iv, 16 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.iv, 16, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (16 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.iv, 16, CK_BYTE);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pData, object->private.length * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pData) {
            Safefree(object->private.pData);
            object->private.pData = 0;
            object->private.length = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* crypt_pkcs11_ck_skipjack_private_wrap_params_new(const char* class) {
    Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_skipjack_private_wrap_params_toBytes(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS));
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_fromBytes(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pPassword) {
        Safefree(object->private.pPassword);
    }
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    if (object->private.pRandomA) {
        Safefree(object->private.pRandomA);
    }
    if (object->private.pPrimeP) {
        Safefree(object->private.pPrimeP);
    }
    if (object->private.pBaseG) {
        Safefree(object->private.pBaseG);
    }
    if (object->private.pSubprimeQ) {
        Safefree(object->private.pSubprimeQ);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pPassword) {
        CK_BYTE_PTR pPassword = 0;
        myNewxz(pPassword, object->private.ulPasswordLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPassword, pPassword, object->private.ulPasswordLen, CK_BYTE);
        object->private.pPassword = pPassword;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = 0;
        myNewxz(pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPublicData, pPublicData, object->private.ulPublicDataLen, CK_BYTE);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pRandomA) {
        CK_BYTE_PTR pRandomA = 0;
        myNewxz(pRandomA, object->private.ulRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pRandomA, pRandomA, object->private.ulRandomLen, CK_BYTE);
        object->private.pRandomA = pRandomA;
    }
    if (object->private.pPrimeP) {
        CK_BYTE_PTR pPrimeP = 0;
        myNewxz(pPrimeP, object->private.ulPAndGLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPrimeP) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPrimeP, pPrimeP, object->private.ulPAndGLen, CK_BYTE);
        object->private.pPrimeP = pPrimeP;
    }
    if (object->private.pBaseG) {
        CK_BYTE_PTR pBaseG = 0;
        myNewxz(pBaseG, object->private.ulPAndGLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pBaseG) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pBaseG, pBaseG, object->private.ulPAndGLen, CK_BYTE);
        object->private.pBaseG = pBaseG;
    }
    if (object->private.pSubprimeQ) {
        CK_BYTE_PTR pSubprimeQ = 0;
        myNewxz(pSubprimeQ, object->private.ulQLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSubprimeQ) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSubprimeQ, pSubprimeQ, object->private.ulQLen, CK_BYTE);
        object->private.pSubprimeQ = pSubprimeQ;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_skipjack_private_wrap_params_DESTROY(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object) {
    if (object) {
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
        }
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
        }
        if (object->private.pRandomA) {
            Safefree(object->private.pRandomA);
        }
        if (object->private.pPrimeP) {
            Safefree(object->private.pPrimeP);
        }
        if (object->private.pBaseG) {
            Safefree(object->private.pBaseG);
        }
        if (object->private.pSubprimeQ) {
            Safefree(object->private.pSubprimeQ);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPassword(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPassword, object->private.ulPasswordLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPassword(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
            object->private.pPassword = 0;
            object->private.ulPasswordLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPassword) {
        Safefree(object->private.pPassword);
    }
    object->private.pPassword = n;
    object->private.ulPasswordLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPublicData(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPublicData(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPublicData) {
            Safefree(object->private.pPublicData);
            object->private.pPublicData = 0;
            object->private.ulPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPublicData) {
        Safefree(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pRandomA(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pRandomA, object->private.ulRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pRandomA(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pRandomA) {
            Safefree(object->private.pRandomA);
            object->private.pRandomA = 0;
            object->private.ulRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pRandomA) {
        Safefree(object->private.pRandomA);
    }
    object->private.pRandomA = n;
    object->private.ulRandomLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPrimeP(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPrimeP, object->private.ulPAndGLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPrimeP(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPrimeP) {
            Safefree(object->private.pPrimeP);
            object->private.pPrimeP = 0;
            object->private.ulPAndGLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPrimeP) {
        Safefree(object->private.pPrimeP);
    }
    object->private.pPrimeP = n;
    object->private.ulPAndGLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pBaseG(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pBaseG, object->private.ulPAndGLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pBaseG(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pBaseG) {
            Safefree(object->private.pBaseG);
            object->private.pBaseG = 0;
            object->private.ulPAndGLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pBaseG) {
        Safefree(object->private.pBaseG);
    }
    object->private.pBaseG = n;
    object->private.ulPAndGLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pSubprimeQ(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSubprimeQ, object->private.ulQLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pSubprimeQ(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSubprimeQ) {
            Safefree(object->private.pSubprimeQ);
            object->private.pSubprimeQ = 0;
            object->private.ulQLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSubprimeQ) {
        Safefree(object->private.pSubprimeQ);
    }
    object->private.pSubprimeQ = n;
    object->private.ulQLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* crypt_pkcs11_ck_skipjack_relayx_params_new(const char* class) {
    Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_skipjack_relayx_params_toBytes(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_SKIPJACK_RELAYX_PARAMS));
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_fromBytes(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_SKIPJACK_RELAYX_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pOldWrappedX) {
        Safefree(object->private.pOldWrappedX);
    }
    if (object->private.pOldPassword) {
        Safefree(object->private.pOldPassword);
    }
    if (object->private.pOldPublicData) {
        Safefree(object->private.pOldPublicData);
    }
    if (object->private.pOldRandomA) {
        Safefree(object->private.pOldRandomA);
    }
    if (object->private.pNewPassword) {
        Safefree(object->private.pNewPassword);
    }
    if (object->private.pNewPublicData) {
        Safefree(object->private.pNewPublicData);
    }
    if (object->private.pNewRandomA) {
        Safefree(object->private.pNewRandomA);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pOldWrappedX) {
        CK_BYTE_PTR pOldWrappedX = 0;
        myNewxz(pOldWrappedX, object->private.ulOldWrappedXLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOldWrappedX) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOldWrappedX, pOldWrappedX, object->private.ulOldWrappedXLen, CK_BYTE);
        object->private.pOldWrappedX = pOldWrappedX;
    }
    if (object->private.pOldPassword) {
        CK_BYTE_PTR pOldPassword = 0;
        myNewxz(pOldPassword, object->private.ulOldPasswordLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOldPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOldPassword, pOldPassword, object->private.ulOldPasswordLen, CK_BYTE);
        object->private.pOldPassword = pOldPassword;
    }
    if (object->private.pOldPublicData) {
        CK_BYTE_PTR pOldPublicData = 0;
        myNewxz(pOldPublicData, object->private.ulOldPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOldPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOldPublicData, pOldPublicData, object->private.ulOldPublicDataLen, CK_BYTE);
        object->private.pOldPublicData = pOldPublicData;
    }
    if (object->private.pOldRandomA) {
        CK_BYTE_PTR pOldRandomA = 0;
        myNewxz(pOldRandomA, object->private.ulOldRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOldRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOldRandomA, pOldRandomA, object->private.ulOldRandomLen, CK_BYTE);
        object->private.pOldRandomA = pOldRandomA;
    }
    if (object->private.pNewPassword) {
        CK_BYTE_PTR pNewPassword = 0;
        myNewxz(pNewPassword, object->private.ulNewPasswordLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pNewPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pNewPassword, pNewPassword, object->private.ulNewPasswordLen, CK_BYTE);
        object->private.pNewPassword = pNewPassword;
    }
    if (object->private.pNewPublicData) {
        CK_BYTE_PTR pNewPublicData = 0;
        myNewxz(pNewPublicData, object->private.ulNewPublicDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pNewPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pNewPublicData, pNewPublicData, object->private.ulNewPublicDataLen, CK_BYTE);
        object->private.pNewPublicData = pNewPublicData;
    }
    if (object->private.pNewRandomA) {
        CK_BYTE_PTR pNewRandomA = 0;
        myNewxz(pNewRandomA, object->private.ulNewRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pNewRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pNewRandomA, pNewRandomA, object->private.ulNewRandomLen, CK_BYTE);
        object->private.pNewRandomA = pNewRandomA;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_skipjack_relayx_params_DESTROY(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object) {
    if (object) {
        if (object->private.pOldWrappedX) {
            Safefree(object->private.pOldWrappedX);
        }
        if (object->private.pOldPassword) {
            Safefree(object->private.pOldPassword);
        }
        if (object->private.pOldPublicData) {
            Safefree(object->private.pOldPublicData);
        }
        if (object->private.pOldRandomA) {
            Safefree(object->private.pOldRandomA);
        }
        if (object->private.pNewPassword) {
            Safefree(object->private.pNewPassword);
        }
        if (object->private.pNewPublicData) {
            Safefree(object->private.pNewPublicData);
        }
        if (object->private.pNewRandomA) {
            Safefree(object->private.pNewRandomA);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldWrappedX(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOldWrappedX, object->private.ulOldWrappedXLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldWrappedX(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOldWrappedX) {
            Safefree(object->private.pOldWrappedX);
            object->private.pOldWrappedX = 0;
            object->private.ulOldWrappedXLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOldWrappedX) {
        Safefree(object->private.pOldWrappedX);
    }
    object->private.pOldWrappedX = n;
    object->private.ulOldWrappedXLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOldPassword, object->private.ulOldPasswordLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOldPassword) {
            Safefree(object->private.pOldPassword);
            object->private.pOldPassword = 0;
            object->private.ulOldPasswordLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOldPassword) {
        Safefree(object->private.pOldPassword);
    }
    object->private.pOldPassword = n;
    object->private.ulOldPasswordLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOldPublicData, object->private.ulOldPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOldPublicData) {
            Safefree(object->private.pOldPublicData);
            object->private.pOldPublicData = 0;
            object->private.ulOldPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOldPublicData) {
        Safefree(object->private.pOldPublicData);
    }
    object->private.pOldPublicData = n;
    object->private.ulOldPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pOldRandomA, object->private.ulOldRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOldRandomA) {
            Safefree(object->private.pOldRandomA);
            object->private.pOldRandomA = 0;
            object->private.ulOldRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pOldRandomA) {
        Safefree(object->private.pOldRandomA);
    }
    object->private.pOldRandomA = n;
    object->private.ulOldRandomLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pNewPassword, object->private.ulNewPasswordLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pNewPassword) {
            Safefree(object->private.pNewPassword);
            object->private.pNewPassword = 0;
            object->private.ulNewPasswordLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pNewPassword) {
        Safefree(object->private.pNewPassword);
    }
    object->private.pNewPassword = n;
    object->private.ulNewPasswordLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pNewPublicData, object->private.ulNewPublicDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pNewPublicData) {
            Safefree(object->private.pNewPublicData);
            object->private.pNewPublicData = 0;
            object->private.ulNewPublicDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pNewPublicData) {
        Safefree(object->private.pNewPublicData);
    }
    object->private.pNewPublicData = n;
    object->private.ulNewPublicDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pNewRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pNewRandomA, object->private.ulNewRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pNewRandomA) {
            Safefree(object->private.pNewRandomA);
            object->private.pNewRandomA = 0;
            object->private.ulNewRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pNewRandomA) {
        Safefree(object->private.pNewRandomA);
    }
    object->private.pNewRandomA = n;
    object->private.ulNewRandomLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_PBE_PARAMS* crypt_pkcs11_ck_pbe_params_new(const char* class) {
    Crypt__PKCS11__CK_PBE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_PBE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pInitVector = 0;
        myNewxz(object->private.pInitVector, 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pInitVector) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
    }
    return object;
}

SV* crypt_pkcs11_ck_pbe_params_toBytes(Crypt__PKCS11__CK_PBE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_PBE_PARAMS));
}

CK_RV crypt_pkcs11_ck_pbe_params_fromBytes(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_PBE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* uncoverable branch 1 */
    if (object->private.pInitVector) {
        Safefree(object->private.pInitVector);
    }
    if (object->private.pPassword) {
        Safefree(object->private.pPassword);
    }
    if (object->private.pSalt) {
        Safefree(object->private.pSalt);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pInitVector) {
        CK_BYTE_PTR pInitVector = 0;
        myNewxz(pInitVector, 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pInitVector) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pInitVector, pInitVector, 8, CK_BYTE);
        object->private.pInitVector = pInitVector;
    }
    else {
        myNewxz(object->private.pInitVector, 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pInitVector) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
    }
    if (object->private.pPassword) {
        CK_CHAR_PTR pPassword = 0;
        myNewxz(pPassword, object->private.ulPasswordLen, CK_CHAR);
        /* uncoverable branch 0 */
        if (!pPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPassword, pPassword, object->private.ulPasswordLen, CK_CHAR);
        object->private.pPassword = pPassword;
    }
    if (object->private.pSalt) {
        CK_BYTE_PTR pSalt = 0;
        myNewxz(pSalt, object->private.ulSaltLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSalt) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSalt, pSalt, object->private.ulSaltLen, CK_BYTE);
        object->private.pSalt = pSalt;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_pbe_params_DESTROY(Crypt__PKCS11__CK_PBE_PARAMS* object) {
    if (object) {
        /* uncoverable branch 1 */
        if (object->private.pInitVector) {
            Safefree(object->private.pInitVector);
        }
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
        }
        if (object->private.pSalt) {
            Safefree(object->private.pSalt);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_pbe_params_get_pInitVector(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pInitVector, 8 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pInitVector(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.pInitVector, 8, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != 8) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.pInitVector, 8, CK_BYTE);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_get_pPassword(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPassword, object->private.ulPasswordLen * sizeof(CK_CHAR));
    sv_utf8_upgrade_nomg(sv);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pPassword(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    CK_CHAR_PTR n = 0;
    CK_CHAR_PTR p;
    STRLEN l;
    SV* _sv;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
            object->private.pPassword = 0;
            object->private.ulPasswordLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(_sv = newSVsv(sv))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    sv_2mortal(_sv);

    sv_utf8_downgrade(_sv, 0);
    if (!(p = SvPV(_sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }

    myNewxz(n, l, CK_CHAR);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_CHAR);
    if (object->private.pPassword) {
        Safefree(object->private.pPassword);
    }
    object->private.pPassword = n;
    object->private.ulPasswordLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_get_pSalt(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSalt, object->private.ulSaltLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pSalt(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSalt) {
            Safefree(object->private.pSalt);
            object->private.pSalt = 0;
            object->private.ulSaltLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSalt) {
        Safefree(object->private.pSalt);
    }
    object->private.pSalt = n;
    object->private.ulSaltLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_get_ulIteration(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulIteration);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_ulIteration(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulIteration = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* crypt_pkcs11_ck_key_wrap_set_oaep_params_new(const char* class) {
    Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_key_wrap_set_oaep_params_toBytes(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS));
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_fromBytes(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pX) {
        Safefree(object->private.pX);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pX) {
        CK_BYTE_PTR pX = 0;
        myNewxz(pX, object->private.ulXLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pX) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pX, pX, object->private.ulXLen, CK_BYTE);
        object->private.pX = pX;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_key_wrap_set_oaep_params_DESTROY(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object) {
    if (object) {
        if (object->private.pX) {
            Safefree(object->private.pX);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_get_bBC(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.bBC);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_set_bBC(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.bBC = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_get_pX(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pX, object->private.ulXLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_set_pX(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pX) {
            Safefree(object->private.pX);
            object->private.pX = 0;
            object->private.ulXLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pX) {
        Safefree(object->private.pX);
    }
    object->private.pX = n;
    object->private.ulXLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_RANDOM_DATA* crypt_pkcs11_ck_ssl3_random_data_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_RANDOM_DATA);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_random_data_toBytes(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_RANDOM_DATA));
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_fromBytes(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_SSL3_RANDOM_DATA))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pClientRandom) {
        Safefree(object->private.pClientRandom);
    }
    if (object->private.pServerRandom) {
        Safefree(object->private.pServerRandom);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pClientRandom) {
        CK_BYTE_PTR pClientRandom = 0;
        myNewxz(pClientRandom, object->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pClientRandom, pClientRandom, object->private.ulClientRandomLen, CK_BYTE);
        object->private.pClientRandom = pClientRandom;
    }
    if (object->private.pServerRandom) {
        CK_BYTE_PTR pServerRandom = 0;
        myNewxz(pServerRandom, object->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pServerRandom, pServerRandom, object->private.ulServerRandomLen, CK_BYTE);
        object->private.pServerRandom = pServerRandom;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ssl3_random_data_DESTROY(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object) {
    if (object) {
        if (object->private.pClientRandom) {
            Safefree(object->private.pClientRandom);
        }
        if (object->private.pServerRandom) {
            Safefree(object->private.pServerRandom);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_get_pClientRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pClientRandom, object->private.ulClientRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_set_pClientRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pClientRandom) {
            Safefree(object->private.pClientRandom);
            object->private.pClientRandom = 0;
            object->private.ulClientRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pClientRandom) {
        Safefree(object->private.pClientRandom);
    }
    object->private.pClientRandom = n;
    object->private.ulClientRandomLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_get_pServerRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pServerRandom, object->private.ulServerRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_set_pServerRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pServerRandom) {
            Safefree(object->private.pServerRandom);
            object->private.pServerRandom = 0;
            object->private.ulServerRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pServerRandom) {
        Safefree(object->private.pServerRandom);
    }
    object->private.pServerRandom = n;
    object->private.ulServerRandomLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* crypt_pkcs11_ck_ssl3_master_key_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pVersion = &(object->pVersion);
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_master_key_derive_params_toBytes(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_fromBytes(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        Safefree(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        Safefree(object->private.RandomInfo.pServerRandom);
    }
    Zero(object->private.pVersion, 1, CK_VERSION);

    Copy(p, &(object->private), l, char);

    if (object->private.RandomInfo.pClientRandom) {
        CK_BYTE_PTR pClientRandom = 0;
        myNewxz(pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.RandomInfo.pClientRandom, pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        object->private.RandomInfo.pClientRandom = pClientRandom;
    }
    if (object->private.RandomInfo.pServerRandom) {
        CK_BYTE_PTR pServerRandom = 0;
        myNewxz(pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.RandomInfo.pServerRandom, pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        object->private.RandomInfo.pServerRandom = pServerRandom;
    }
    /* uncoverable branch 1 */
    if (object->private.pVersion) {
        Copy(object->private.pVersion, &(object->pVersion), 1, CK_VERSION);
    }
    object->private.pVersion = &(object->pVersion);

    return CKR_OK;
}

void crypt_pkcs11_ck_ssl3_master_key_derive_params_DESTROY(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.RandomInfo.pClientRandom) {
            Safefree(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            Safefree(object->private.RandomInfo.pServerRandom);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_get_RandomInfo(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        myNewxz(pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.RandomInfo.pServerRandom) {
        myNewxz(pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(object->private.RandomInfo.pClientRandom, pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(object->private.RandomInfo.pServerRandom, pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
    }

    if (sv->private.pClientRandom) {
        Safefree(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        Safefree(sv->private.pServerRandom);
    }

    sv->private.pClientRandom = pClientRandom;
    sv->private.ulClientRandomLen = object->private.RandomInfo.ulClientRandomLen;
    sv->private.pServerRandom = pServerRandom;
    sv->private.ulServerRandomLen = object->private.RandomInfo.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_set_RandomInfo(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.pClientRandom) {
        myNewxz(pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (sv->private.pServerRandom) {
        myNewxz(pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(sv->private.pClientRandom, pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(sv->private.pServerRandom, pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
    }

    if (object->private.RandomInfo.pClientRandom) {
        Safefree(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        Safefree(object->private.RandomInfo.pServerRandom);
    }

    object->private.RandomInfo.pClientRandom = pClientRandom;
    object->private.RandomInfo.ulClientRandomLen = sv->private.ulClientRandomLen;
    object->private.RandomInfo.pServerRandom = pServerRandom;
    object->private.RandomInfo.ulServerRandomLen = sv->private.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_get_pVersion(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, Crypt__PKCS11__CK_VERSION* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    sv->private.major = object->pVersion.major;
    sv->private.minor = object->pVersion.minor;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_set_pVersion(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, Crypt__PKCS11__CK_VERSION* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    object->pVersion.major = sv->private.major;
    object->pVersion.minor = sv->private.minor;

    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* crypt_pkcs11_ck_ssl3_key_mat_out_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_key_mat_out_toBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_KEY_MAT_OUT));
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_fromBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

void crypt_pkcs11_ck_ssl3_key_mat_out_DESTROY(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object) {
    if (object) {
        if (object->private.pIVClient) {
            Safefree(object->private.pIVClient);
        }
        if (object->private.pIVServer) {
            Safefree(object->private.pIVServer);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hClientMacSecret);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hClientMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hClientMacSecret = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hServerMacSecret);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hServerMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hServerMacSecret = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hClientKey);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hClientKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hClientKey = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hServerKey);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hServerKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hServerKey = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVClient(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pIVClient, object->ulIVClient * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVClient(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVServer(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pIVServer, object->ulIVServer * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVServer(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* crypt_pkcs11_ck_ssl3_key_mat_params_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pReturnedKeyMaterial = &(object->pReturnedKeyMaterial);
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_key_mat_params_toBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_KEY_MAT_PARAMS));
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_fromBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

void crypt_pkcs11_ck_ssl3_key_mat_params_DESTROY(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object) {
    if (object) {
        if (object->private.RandomInfo.pClientRandom) {
            Safefree(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            Safefree(object->private.RandomInfo.pServerRandom);
        }
        if (object->pReturnedKeyMaterial.pIVClient) {
            Safefree(object->pReturnedKeyMaterial.pIVClient);
        }
        if (object->pReturnedKeyMaterial.pIVServer) {
            Safefree(object->pReturnedKeyMaterial.pIVServer);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_ulMacSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulMacSizeInBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_ulMacSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulMacSizeInBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_ulKeySizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulKeySizeInBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_ulKeySizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulKeySizeInBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_ulIVSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulIVSizeInBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_ulIVSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulIVSizeInBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_bIsExport(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.bIsExport);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_bIsExport(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (SvUV(sv)) {
        object->private.bIsExport = CK_TRUE;
    }
    else {
        object->private.bIsExport = CK_FALSE;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_RandomInfo(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        myNewxz(pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.RandomInfo.pServerRandom) {
        myNewxz(pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(object->private.RandomInfo.pClientRandom, pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(object->private.RandomInfo.pServerRandom, pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
    }

    if (sv->private.pClientRandom) {
        Safefree(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        Safefree(sv->private.pServerRandom);
    }

    sv->private.pClientRandom = pClientRandom;
    sv->private.ulClientRandomLen = object->private.RandomInfo.ulClientRandomLen;
    sv->private.pServerRandom = pServerRandom;
    sv->private.ulServerRandomLen = object->private.RandomInfo.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_RandomInfo(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, Crypt__PKCS11__CK_SSL3_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.pClientRandom) {
        myNewxz(pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (sv->private.pServerRandom) {
        myNewxz(pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(sv->private.pClientRandom, pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(sv->private.pServerRandom, pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
    }

    if (object->private.RandomInfo.pClientRandom) {
        Safefree(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        Safefree(object->private.RandomInfo.pServerRandom);
    }

    object->private.RandomInfo.pClientRandom = pClientRandom;
    object->private.RandomInfo.ulClientRandomLen = sv->private.ulClientRandomLen;
    object->private.RandomInfo.pServerRandom = pServerRandom;
    object->private.RandomInfo.ulServerRandomLen = sv->private.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_pReturnedKeyMaterial(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* sv) {
    CK_BYTE_PTR pIVClient = NULL_PTR;
    CK_BYTE_PTR pIVServer = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((object->private.ulIVSizeInBits % 8)) {
        return CKR_GENERAL_ERROR;
    }

    if (object->private.ulIVSizeInBits) {
        myNewxz(pIVClient, object->private.ulIVSizeInBits / 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIVClient) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.ulIVSizeInBits) {
        myNewxz(pIVServer, object->private.ulIVSizeInBits / 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIVServer) {
            /* uncoverable begin */
            Safefree(pIVClient);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    /* uncoverable branch 2 */
    if (pIVClient && object->pReturnedKeyMaterial.pIVClient) {
        /* uncoverable block 0 */
        Copy(object->pReturnedKeyMaterial.pIVClient, pIVClient, (object->private.ulIVSizeInBits / 8), CK_BYTE);
    }
    /* uncoverable branch 2 */
    if (pIVServer && object->pReturnedKeyMaterial.pIVServer) {
        /* uncoverable block 0 */
        Copy(object->pReturnedKeyMaterial.pIVServer, pIVServer, (object->private.ulIVSizeInBits / 8), CK_BYTE);
    }

    if (sv->private.pIVClient) {
        Safefree(sv->private.pIVClient);
    }
    if (sv->private.pIVServer) {
        Safefree(sv->private.pIVServer);
    }

    sv->private.hClientMacSecret = object->pReturnedKeyMaterial.hClientMacSecret;
    sv->private.hServerMacSecret = object->pReturnedKeyMaterial.hServerMacSecret;
    sv->private.hClientKey = object->pReturnedKeyMaterial.hClientKey;
    sv->private.hServerKey = object->pReturnedKeyMaterial.hServerKey;
    sv->private.pIVClient = pIVClient;

    if (pIVClient) {
        sv->ulIVClient = (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE);
    }
    else {
        sv->ulIVClient = 0;
    }
    sv->private.pIVServer = pIVServer;
    if (pIVServer) {
        sv->ulIVServer = (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE);
    }
    else {
        sv->ulIVServer = 0;
    }

    return CKR_OK;
}

Crypt__PKCS11__CK_TLS_PRF_PARAMS* crypt_pkcs11_ck_tls_prf_params_new(const char* class) {
    Crypt__PKCS11__CK_TLS_PRF_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_TLS_PRF_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_tls_prf_params_toBytes(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_TLS_PRF_PARAMS));
}

CK_RV crypt_pkcs11_ck_tls_prf_params_fromBytes(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_TLS_PRF_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSeed) {
        Safefree(object->private.pSeed);
    }
    if (object->private.pLabel) {
        Safefree(object->private.pLabel);
    }
    if (object->private.pOutput) {
        Safefree(object->private.pOutput);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSeed) {
        CK_BYTE_PTR pSeed = 0;
        myNewxz(pSeed, object->private.ulSeedLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSeed) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSeed, pSeed, object->private.ulSeedLen, CK_BYTE);
        object->private.pSeed = pSeed;
    }
    if (object->private.pLabel) {
        CK_BYTE_PTR pLabel = 0;
        myNewxz(pLabel, object->private.ulLabelLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pLabel) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pLabel, pLabel, object->private.ulLabelLen, CK_BYTE);
        object->private.pLabel = pLabel;
    }
    if (object->private.pulOutputLen) {
        object->pulOutputLen = *(object->private.pulOutputLen);
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    if (object->private.pOutput) {
        CK_BYTE_PTR pOutput = 0;
        myNewxz(pOutput, object->pulOutputLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOutput) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOutput, pOutput, object->pulOutputLen, CK_BYTE);
        object->private.pOutput = pOutput;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_tls_prf_params_DESTROY(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object) {
    if (object) {
        if (object->private.pSeed) {
            Safefree(object->private.pSeed);
        }
        if (object->private.pLabel) {
            Safefree(object->private.pLabel);
        }
        if (object->private.pOutput) {
            Safefree(object->private.pOutput);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pSeed(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSeed, object->private.ulSeedLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pSeed(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSeed) {
            Safefree(object->private.pSeed);
            object->private.pSeed = 0;
            object->private.ulSeedLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSeed) {
        Safefree(object->private.pSeed);
    }
    object->private.pSeed = n;
    object->private.ulSeedLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pLabel(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pLabel, object->private.ulLabelLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pLabel(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pLabel) {
            Safefree(object->private.pLabel);
            object->private.pLabel = 0;
            object->private.ulLabelLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pLabel) {
        Safefree(object->private.pLabel);
    }
    object->private.pLabel = n;
    object->private.ulLabelLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pOutput(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (!object->pulOutputLen) {
            return CKR_FUNCTION_FAILED;
        }

        /* uncoverable branch 1 */
        if (object->private.pOutput) {
            Safefree(object->private.pOutput);
        }

        object->private.pOutput = 0;
        myNewxz(object->private.pOutput, object->pulOutputLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pOutput) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.pOutput && object->pulOutputLen) {
        sv_setpvn(sv, object->private.pOutput, object->pulOutputLen * sizeof(CK_BYTE));
    }
    else {
        sv_setsv(sv, &PL_sv_undef);
    }
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pOutput(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    UV l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOutput) {
            Safefree(object->private.pOutput);
            object->private.pOutput = 0;
        }
        object->private.pulOutputLen = &(object->pulOutputLen);
        object->pulOutputLen = 0;
        return CKR_OK;
    }

    if (!crypt_pkcs11_xs_SvUOK(sv)
        || !(l = SvUV(sv)))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pOutput) {
        Safefree(object->private.pOutput);
    }

    object->private.pOutput = 0;
    myNewxz(object->private.pOutput, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!object->private.pOutput) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    object->pulOutputLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_RANDOM_DATA* crypt_pkcs11_ck_wtls_random_data_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_RANDOM_DATA);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_random_data_toBytes(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_RANDOM_DATA));
}

CK_RV crypt_pkcs11_ck_wtls_random_data_fromBytes(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_WTLS_RANDOM_DATA))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pClientRandom) {
        Safefree(object->private.pClientRandom);
    }
    if (object->private.pServerRandom) {
        Safefree(object->private.pServerRandom);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pClientRandom) {
        CK_BYTE_PTR pClientRandom = 0;
        myNewxz(pClientRandom, object->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pClientRandom, pClientRandom, object->private.ulClientRandomLen, CK_BYTE);
        object->private.pClientRandom = pClientRandom;
    }
    if (object->private.pServerRandom) {
        CK_BYTE_PTR pServerRandom = 0;
        myNewxz(pServerRandom, object->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pServerRandom, pServerRandom, object->private.ulServerRandomLen, CK_BYTE);
        object->private.pServerRandom = pServerRandom;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_wtls_random_data_DESTROY(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object) {
    if (object) {
        if (object->private.pClientRandom) {
            Safefree(object->private.pClientRandom);
        }
        if (object->private.pServerRandom) {
            Safefree(object->private.pServerRandom);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_wtls_random_data_get_pClientRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pClientRandom, object->private.ulClientRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_set_pClientRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pClientRandom) {
            Safefree(object->private.pClientRandom);
            object->private.pClientRandom = 0;
            object->private.ulClientRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pClientRandom) {
        Safefree(object->private.pClientRandom);
    }
    object->private.pClientRandom = n;
    object->private.ulClientRandomLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_get_pServerRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pServerRandom, object->private.ulServerRandomLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_set_pServerRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pServerRandom) {
            Safefree(object->private.pServerRandom);
            object->private.pServerRandom = 0;
            object->private.ulServerRandomLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pServerRandom) {
        Safefree(object->private.pServerRandom);
    }
    object->private.pServerRandom = n;
    object->private.ulServerRandomLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* crypt_pkcs11_ck_wtls_master_key_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pVersion = 0;
        myNewxz(object->private.pVersion, 1, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pVersion) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_master_key_derive_params_toBytes(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS));
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_fromBytes(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        Safefree(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        Safefree(object->private.RandomInfo.pServerRandom);
    }
    /* uncoverable branch 1 */
    if (object->private.pVersion) {
        Safefree(object->private.pVersion);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.RandomInfo.pClientRandom) {
        CK_BYTE_PTR pClientRandom = 0;
        myNewxz(pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.RandomInfo.pClientRandom, pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        object->private.RandomInfo.pClientRandom = pClientRandom;
    }
    if (object->private.RandomInfo.pServerRandom) {
        CK_BYTE_PTR pServerRandom = 0;
        myNewxz(pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.RandomInfo.pServerRandom, pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        object->private.RandomInfo.pServerRandom = pServerRandom;
    }
    /* uncoverable branch 1 */
    if (object->private.pVersion) {
        CK_BYTE_PTR pVersion = 0;
        myNewxz(pVersion, 1, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pVersion) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pVersion, pVersion, 1, CK_BYTE);
        object->private.pVersion = pVersion;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_wtls_master_key_derive_params_DESTROY(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.RandomInfo.pClientRandom) {
            Safefree(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            Safefree(object->private.RandomInfo.pServerRandom);
        }
        /* uncoverable branch 1 */
        if (object->private.pVersion) {
            Safefree(object->private.pVersion);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_get_DigestMechanism(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.DigestMechanism);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_set_DigestMechanism(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.DigestMechanism = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_get_RandomInfo(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        myNewxz(pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.RandomInfo.pServerRandom) {
        myNewxz(pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(object->private.RandomInfo.pClientRandom, pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(object->private.RandomInfo.pServerRandom, pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
    }

    if (sv->private.pClientRandom) {
        Safefree(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        Safefree(sv->private.pServerRandom);
    }

    sv->private.pClientRandom = pClientRandom;
    sv->private.ulClientRandomLen = object->private.RandomInfo.ulClientRandomLen;
    sv->private.pServerRandom = pServerRandom;
    sv->private.ulServerRandomLen = object->private.RandomInfo.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_set_RandomInfo(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.pClientRandom) {
        myNewxz(pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (sv->private.pServerRandom) {
        myNewxz(pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(sv->private.pClientRandom, pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(sv->private.pServerRandom, pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
    }

    if (object->private.RandomInfo.pClientRandom) {
        Safefree(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        Safefree(object->private.RandomInfo.pServerRandom);
    }

    object->private.RandomInfo.pClientRandom = pClientRandom;
    object->private.RandomInfo.ulClientRandomLen = sv->private.ulClientRandomLen;
    object->private.RandomInfo.pServerRandom = pServerRandom;
    object->private.RandomInfo.ulServerRandomLen = sv->private.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_get_pVersion(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, *(object->private.pVersion));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_set_pVersion(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_WTLS_PRF_PARAMS* crypt_pkcs11_ck_wtls_prf_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_PRF_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_prf_params_toBytes(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_PRF_PARAMS));
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_fromBytes(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_WTLS_PRF_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSeed) {
        Safefree(object->private.pSeed);
    }
    if (object->private.pLabel) {
        Safefree(object->private.pLabel);
    }
    if (object->private.pOutput) {
        Safefree(object->private.pOutput);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSeed) {
        CK_BYTE_PTR pSeed = 0;
        myNewxz(pSeed, object->private.ulSeedLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSeed) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSeed, pSeed, object->private.ulSeedLen, CK_BYTE);
        object->private.pSeed = pSeed;
    }
    if (object->private.pLabel) {
        CK_BYTE_PTR pLabel = 0;
        myNewxz(pLabel, object->private.ulLabelLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pLabel) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pLabel, pLabel, object->private.ulLabelLen, CK_BYTE);
        object->private.pLabel = pLabel;
    }
    if (object->private.pulOutputLen) {
        object->pulOutputLen = *(object->private.pulOutputLen);
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    if (object->private.pOutput) {
        CK_BYTE_PTR pOutput = 0;
        myNewxz(pOutput, object->pulOutputLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pOutput) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pOutput, pOutput, object->pulOutputLen, CK_BYTE);
        object->private.pOutput = pOutput;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_wtls_prf_params_DESTROY(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object) {
    if (object) {
        if (object->private.pSeed) {
            Safefree(object->private.pSeed);
        }
        if (object->private.pLabel) {
            Safefree(object->private.pLabel);
        }
        if (object->private.pOutput) {
            Safefree(object->private.pOutput);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_DigestMechanism(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.DigestMechanism);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_DigestMechanism(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.DigestMechanism = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pSeed(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSeed, object->private.ulSeedLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pSeed(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSeed) {
            Safefree(object->private.pSeed);
            object->private.pSeed = 0;
            object->private.ulSeedLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSeed) {
        Safefree(object->private.pSeed);
    }
    object->private.pSeed = n;
    object->private.ulSeedLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pLabel(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pLabel, object->private.ulLabelLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pLabel(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pLabel) {
            Safefree(object->private.pLabel);
            object->private.pLabel = 0;
            object->private.ulLabelLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pLabel) {
        Safefree(object->private.pLabel);
    }
    object->private.pLabel = n;
    object->private.ulLabelLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pOutput(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (!object->pulOutputLen) {
            return CKR_FUNCTION_FAILED;
        }

        /* uncoverable branch 1 */
        if (object->private.pOutput) {
            Safefree(object->private.pOutput);
        }

        object->private.pOutput = 0;
        myNewxz(object->private.pOutput, object->pulOutputLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!object->private.pOutput) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.pOutput && object->pulOutputLen) {
        sv_setpvn(sv, object->private.pOutput, object->pulOutputLen * sizeof(CK_BYTE));
    }
    else {
        sv_setsv(sv, &PL_sv_undef);
    }
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pOutput(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    UV l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pOutput) {
            Safefree(object->private.pOutput);
            object->private.pOutput = 0;
        }
        object->private.pulOutputLen = &(object->pulOutputLen);
        object->pulOutputLen = 0;
        return CKR_OK;
    }

    if (!crypt_pkcs11_xs_SvUOK(sv)
        || !(l = SvUV(sv)))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pOutput) {
        Safefree(object->private.pOutput);
    }

    object->private.pOutput = 0;
    myNewxz(object->private.pOutput, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!object->private.pOutput) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    object->pulOutputLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* crypt_pkcs11_ck_wtls_key_mat_out_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_key_mat_out_toBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_KEY_MAT_OUT));
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_fromBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

void crypt_pkcs11_ck_wtls_key_mat_out_DESTROY(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object) {
    if (object) {
        if (object->private.pIV) {
            Safefree(object->private.pIV);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_get_hMacSecret(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hMacSecret);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_hMacSecret(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hMacSecret = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_get_hKey(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hKey);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_hKey(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hKey = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_get_pIV(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pIV, object->ulIV * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_pIV(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* crypt_pkcs11_ck_wtls_key_mat_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pReturnedKeyMaterial = &(object->pReturnedKeyMaterial);
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_key_mat_params_toBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_KEY_MAT_PARAMS));
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_fromBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

void crypt_pkcs11_ck_wtls_key_mat_params_DESTROY(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object) {
    if (object) {
        if (object->private.RandomInfo.pClientRandom) {
            Safefree(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            Safefree(object->private.RandomInfo.pServerRandom);
        }
        if (object->pReturnedKeyMaterial.pIV) {
            Safefree(object->pReturnedKeyMaterial.pIV);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_DigestMechanism(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.DigestMechanism);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_DigestMechanism(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.DigestMechanism = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulMacSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulMacSizeInBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulMacSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulMacSizeInBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulKeySizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulKeySizeInBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulKeySizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulKeySizeInBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulIVSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulIVSizeInBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulIVSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulIVSizeInBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulSequenceNumber(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulSequenceNumber);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulSequenceNumber(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulSequenceNumber = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_bIsExport(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.bIsExport);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_bIsExport(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (SvUV(sv)) {
        object->private.bIsExport = CK_TRUE;
    }
    else {
        object->private.bIsExport = CK_FALSE;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_RandomInfo(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        myNewxz(pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (object->private.RandomInfo.pServerRandom) {
        myNewxz(pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(object->private.RandomInfo.pClientRandom, pClientRandom, object->private.RandomInfo.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(object->private.RandomInfo.pServerRandom, pServerRandom, object->private.RandomInfo.ulServerRandomLen, CK_BYTE);
    }

    if (sv->private.pClientRandom) {
        Safefree(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        Safefree(sv->private.pServerRandom);
    }

    sv->private.pClientRandom = pClientRandom;
    sv->private.ulClientRandomLen = object->private.RandomInfo.ulClientRandomLen;
    sv->private.pServerRandom = pServerRandom;
    sv->private.ulServerRandomLen = object->private.RandomInfo.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_RandomInfo(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, Crypt__PKCS11__CK_WTLS_RANDOM_DATA* sv) {
    CK_BYTE_PTR pClientRandom = NULL_PTR;
    CK_BYTE_PTR pServerRandom = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.pClientRandom) {
        myNewxz(pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }
    if (sv->private.pServerRandom) {
        myNewxz(pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable begin */
            Safefree(pClientRandom);
            return CKR_HOST_MEMORY;
            /* uncoverable end */
        }
    }

    if (pClientRandom) {
        Copy(sv->private.pClientRandom, pClientRandom, sv->private.ulClientRandomLen, CK_BYTE);
    }
    if (pServerRandom) {
        Copy(sv->private.pServerRandom, pServerRandom, sv->private.ulServerRandomLen, CK_BYTE);
    }

    if (object->private.RandomInfo.pClientRandom) {
        Safefree(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        Safefree(object->private.RandomInfo.pServerRandom);
    }

    object->private.RandomInfo.pClientRandom = pClientRandom;
    object->private.RandomInfo.ulClientRandomLen = sv->private.ulClientRandomLen;
    object->private.RandomInfo.pServerRandom = pServerRandom;
    object->private.RandomInfo.ulServerRandomLen = sv->private.ulServerRandomLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_pReturnedKeyMaterial(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* sv) {
    CK_BYTE_PTR pIV = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((object->private.ulIVSizeInBits % 8)) {
        return CKR_GENERAL_ERROR;
    }

    if (object->private.ulIVSizeInBits) {
        myNewxz(pIV, object->private.ulIVSizeInBits / 8, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIV) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    /* uncoverable branch 2 */
    if (pIV && object->pReturnedKeyMaterial.pIV) {
        /* uncoverable block 0 */
        Copy(object->pReturnedKeyMaterial.pIV, pIV, (object->private.ulIVSizeInBits / 8), CK_BYTE);
    }

    if (sv->private.pIV) {
        Safefree(sv->private.pIV);
    }

    sv->private.hMacSecret = object->pReturnedKeyMaterial.hMacSecret;
    sv->private.hKey = object->pReturnedKeyMaterial.hKey;
    sv->private.pIV = pIV;
    if (pIV) {
        sv->ulIV = (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE);
    }
    else {
        sv->ulIV = 0;
    }

    return CKR_OK;
}

Crypt__PKCS11__CK_CMS_SIG_PARAMS* crypt_pkcs11_ck_cms_sig_params_new(const char* class) {
    Crypt__PKCS11__CK_CMS_SIG_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_CMS_SIG_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pSigningMechanism = &(object->pSigningMechanism);
        object->private.pDigestMechanism = &(object->pDigestMechanism);
    }
    return object;
}

SV* crypt_pkcs11_ck_cms_sig_params_toBytes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_CMS_SIG_PARAMS));
}

CK_RV crypt_pkcs11_ck_cms_sig_params_fromBytes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_CMS_SIG_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->pSigningMechanism.pParameter) {
        Safefree(object->pSigningMechanism.pParameter);
    }
    Zero(&(object->pSigningMechanism), 1, CK_MECHANISM);
    if (object->pDigestMechanism.pParameter) {
        Safefree(object->pDigestMechanism.pParameter);
    }
    Zero(&(object->pDigestMechanism), 1, CK_MECHANISM);
    if (object->private.pContentType) {
        Safefree(object->private.pContentType);
    }
    if (object->private.pRequestedAttributes) {
        Safefree(object->private.pRequestedAttributes);
    }
    if (object->private.pRequiredAttributes) {
        Safefree(object->private.pRequiredAttributes);
    }
    Copy(p, &(object->private), l, char);

    /* uncoverable branch 1 */
    if (object->private.pSigningMechanism) {
        Copy(object->private.pSigningMechanism, &(object->pSigningMechanism), 1, CK_MECHANISM);
        if (object->pSigningMechanism.pParameter) {
            CK_VOID_PTR pParameter = 0;
            myNewxz(pParameter, object->pSigningMechanism.ulParameterLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            Copy(object->pSigningMechanism.pParameter, pParameter, object->pSigningMechanism.ulParameterLen, CK_BYTE);
            object->pSigningMechanism.pParameter = pParameter;
        }
    }
    object->private.pSigningMechanism = &(object->pSigningMechanism);

    /* uncoverable branch 1 */
    if (object->private.pDigestMechanism) {
        Copy(object->private.pDigestMechanism, &(object->pDigestMechanism), 1, CK_MECHANISM);
        if (object->pDigestMechanism.pParameter) {
            CK_VOID_PTR pParameter = 0;
            myNewxz(pParameter, object->pDigestMechanism.ulParameterLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            Copy(object->pDigestMechanism.pParameter, pParameter, object->pDigestMechanism.ulParameterLen, CK_BYTE);
            object->pDigestMechanism.pParameter = pParameter;
        }
    }
    object->private.pDigestMechanism = &(object->pDigestMechanism);

    if (object->private.pContentType) {
        CK_CHAR_PTR pContentType = savepv(object->private.pContentType);
        /* uncoverable branch 0 */
        if (!pContentType) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        object->private.pContentType = pContentType;
    }
    if (object->private.pRequestedAttributes) {
        CK_BYTE_PTR pRequestedAttributes = 0;
        myNewxz(pRequestedAttributes, object->private.ulRequestedAttributesLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pRequestedAttributes) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pRequestedAttributes, pRequestedAttributes, object->private.ulRequestedAttributesLen, CK_BYTE);
        object->private.pRequestedAttributes = pRequestedAttributes;
    }
    if (object->private.pRequiredAttributes) {
        CK_BYTE_PTR pRequiredAttributes = 0;
        myNewxz(pRequiredAttributes, object->private.ulRequiredAttributesLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pRequiredAttributes) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pRequiredAttributes, pRequiredAttributes, object->private.ulRequiredAttributesLen, CK_BYTE);
        object->private.pRequiredAttributes = pRequiredAttributes;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_cms_sig_params_DESTROY(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object) {
    if (object) {
        if (object->pSigningMechanism.pParameter) {
            Safefree(object->pSigningMechanism.pParameter);
        }
        if (object->pDigestMechanism.pParameter) {
            Safefree(object->pDigestMechanism.pParameter);
        }
        if (object->private.pContentType) {
            Safefree(object->private.pContentType);
        }
        if (object->private.pRequestedAttributes) {
            Safefree(object->private.pRequestedAttributes);
        }
        if (object->private.pRequiredAttributes) {
            Safefree(object->private.pRequiredAttributes);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_certificateHandle(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.certificateHandle);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_certificateHandle(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.certificateHandle = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pSigningMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->pSigningMechanism.ulParameterLen) {
        myNewxz(pParameter, object->pSigningMechanism.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(object->pSigningMechanism.pParameter, pParameter, object->pSigningMechanism.ulParameterLen, CK_BYTE);
    }

    if (sv->private.pParameter) {
        Safefree(sv->private.pParameter);
    }
    sv->private.mechanism = object->pSigningMechanism.mechanism;
    sv->private.pParameter = pParameter;
    sv->private.ulParameterLen = object->pSigningMechanism.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pSigningMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.ulParameterLen) {
        myNewxz(pParameter, sv->private.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(sv->private.pParameter, pParameter, sv->private.ulParameterLen, CK_BYTE);
    }

    if (object->pSigningMechanism.pParameter) {
        Safefree(object->pSigningMechanism.pParameter);
    }
    object->pSigningMechanism.mechanism = sv->private.mechanism;
    object->pSigningMechanism.pParameter = pParameter;
    object->pSigningMechanism.ulParameterLen = sv->private.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pDigestMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->pDigestMechanism.ulParameterLen) {
        myNewxz(pParameter, object->pDigestMechanism.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(object->pDigestMechanism.pParameter, pParameter, object->pDigestMechanism.ulParameterLen, CK_BYTE);
    }

    if (sv->private.pParameter) {
        Safefree(sv->private.pParameter);
    }
    sv->private.mechanism = object->pDigestMechanism.mechanism;
    sv->private.pParameter = pParameter;
    sv->private.ulParameterLen = object->pDigestMechanism.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pDigestMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.ulParameterLen) {
        myNewxz(pParameter, sv->private.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(sv->private.pParameter, pParameter, sv->private.ulParameterLen, CK_BYTE);
    }

    if (object->pDigestMechanism.pParameter) {
        Safefree(object->pDigestMechanism.pParameter);
    }
    object->pDigestMechanism.mechanism = sv->private.mechanism;
    object->pDigestMechanism.pParameter = pParameter;
    object->pDigestMechanism.ulParameterLen = sv->private.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pContentType(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpv(sv, object->private.pContentType);
    sv_utf8_upgrade_nomg(sv);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pContentType(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    CK_CHAR_PTR n = 0;
    CK_CHAR_PTR p;
    STRLEN l;
    SV* _sv;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pContentType) {
            Safefree(object->private.pContentType);
            object->private.pContentType = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(_sv = newSVsv(sv))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    sv_2mortal(_sv);

    sv_utf8_downgrade(_sv, 0);
    if (!(p = SvPV(_sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }

    myNewxz(n, l + 1, CK_CHAR);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_CHAR);
    if (object->private.pContentType) {
        Safefree(object->private.pContentType);
    }
    object->private.pContentType = n;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pRequestedAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pRequestedAttributes, object->private.ulRequestedAttributesLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pRequestedAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pRequestedAttributes) {
            Safefree(object->private.pRequestedAttributes);
            object->private.pRequestedAttributes = 0;
            object->private.ulRequestedAttributesLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pRequestedAttributes) {
        Safefree(object->private.pRequestedAttributes);
    }
    object->private.pRequestedAttributes = n;
    object->private.ulRequestedAttributesLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pRequiredAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pRequiredAttributes, object->private.ulRequiredAttributesLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pRequiredAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pRequiredAttributes) {
            Safefree(object->private.pRequiredAttributes);
            object->private.pRequiredAttributes = 0;
            object->private.ulRequiredAttributesLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pRequiredAttributes) {
        Safefree(object->private.pRequiredAttributes);
    }
    object->private.pRequiredAttributes = n;
    object->private.ulRequiredAttributesLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* crypt_pkcs11_ck_key_derivation_string_data_new(const char* class) {
    Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_key_derivation_string_data_toBytes(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_KEY_DERIVATION_STRING_DATA));
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_fromBytes(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_KEY_DERIVATION_STRING_DATA))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pData) {
        CK_BYTE_PTR pData = 0;
        myNewxz(pData, object->private.ulLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pData, pData, object->private.ulLen, CK_BYTE);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_key_derivation_string_data_DESTROY(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object) {
    if (object) {
        if (object->private.pData) {
            Safefree(object->private.pData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_get_pData(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pData, object->private.ulLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_set_pData(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pData) {
            Safefree(object->private.pData);
            object->private.pData = 0;
            object->private.ulLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    object->private.pData = n;
    object->private.ulLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* crypt_pkcs11_ck_pkcs5_pbkd2_params_new(const char* class) {
    Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_pkcs5_pbkd2_params_toBytes(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_PKCS5_PBKD2_PARAMS));
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_fromBytes(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_PKCS5_PBKD2_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pSaltSourceData) {
        Safefree(object->private.pSaltSourceData);
    }
    if (object->private.pPrfData) {
        Safefree(object->private.pPrfData);
    }
    if (object->private.pPassword) {
        Safefree(object->private.pPassword);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pSaltSourceData) {
        CK_BYTE_PTR pSaltSourceData = 0;
        myNewxz(pSaltSourceData, object->private.ulSaltSourceDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSaltSourceData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSaltSourceData, pSaltSourceData, object->private.ulSaltSourceDataLen, CK_BYTE);
        object->private.pSaltSourceData = pSaltSourceData;
    }
    if (object->private.pPrfData) {
        CK_BYTE_PTR pPrfData = 0;
        myNewxz(pPrfData, object->private.ulPrfDataLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pPrfData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPrfData, pPrfData, object->private.ulPrfDataLen, CK_BYTE);
        object->private.pPrfData = pPrfData;
    }
    if (object->private.ulPasswordLen) {
        object->ulPasswordLen = *(object->private.ulPasswordLen);
    }
    object->private.ulPasswordLen = &(object->ulPasswordLen);
    if (object->private.pPassword) {
        CK_CHAR_PTR pPassword = 0;
        myNewxz(pPassword, object->ulPasswordLen, CK_CHAR);
        /* uncoverable branch 0 */
        if (!pPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pPassword, pPassword, object->ulPasswordLen, CK_CHAR);
        object->private.pPassword = pPassword;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_pkcs5_pbkd2_params_DESTROY(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object) {
    if (object) {
        if (object->private.pSaltSourceData) {
            Safefree(object->private.pSaltSourceData);
        }
        if (object->private.pPrfData) {
            Safefree(object->private.pPrfData);
        }
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_saltSource(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.saltSource);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_saltSource(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.saltSource = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pSaltSourceData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSaltSourceData, object->private.ulSaltSourceDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pSaltSourceData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSaltSourceData) {
            Safefree(object->private.pSaltSourceData);
            object->private.pSaltSourceData = 0;
            object->private.ulSaltSourceDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSaltSourceData) {
        Safefree(object->private.pSaltSourceData);
    }
    object->private.pSaltSourceData = n;
    object->private.ulSaltSourceDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_iterations(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.iterations);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_iterations(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.iterations = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_prf(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.prf);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_prf(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.prf = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPrfData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pPrfData, object->private.ulPrfDataLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPrfData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPrfData) {
            Safefree(object->private.pPrfData);
            object->private.pPrfData = 0;
            object->private.ulPrfDataLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pPrfData) {
        Safefree(object->private.pPrfData);
    }
    object->private.pPrfData = n;
    object->private.ulPrfDataLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPassword(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (!object->ulPasswordLen) {
            return CKR_FUNCTION_FAILED;
        }

        /* uncoverable branch 1 */
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
        }

        object->private.pPassword = 0;
        myNewxz(object->private.pPassword, object->ulPasswordLen, CK_CHAR);
        /* uncoverable branch 0 */
        if (!object->private.pPassword) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.pPassword && object->ulPasswordLen) {
        sv_setpvn(sv, object->private.pPassword, object->ulPasswordLen * sizeof(CK_CHAR));
        sv_utf8_upgrade(sv);
    }
    else {
        sv_setsv(sv, &PL_sv_undef);
    }
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPassword(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    UV l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pPassword) {
            Safefree(object->private.pPassword);
            object->private.pPassword = 0;
        }
        object->private.ulPasswordLen = &(object->ulPasswordLen);
        object->ulPasswordLen = 0;
        return CKR_OK;
    }

    if (!crypt_pkcs11_xs_SvUOK(sv)
        || !(l = SvUV(sv)))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pPassword) {
        Safefree(object->private.pPassword);
    }

    object->private.pPassword = 0;
    myNewxz(object->private.pPassword, l, CK_CHAR);
    /* uncoverable branch 0 */
    if (!object->private.pPassword) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.ulPasswordLen = &(object->ulPasswordLen);
    object->ulPasswordLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAM* crypt_pkcs11_ck_otp_param_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAM* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_OTP_PARAM);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_otp_param_toBytes(Crypt__PKCS11__CK_OTP_PARAM* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_OTP_PARAM));
}

CK_RV crypt_pkcs11_ck_otp_param_fromBytes(Crypt__PKCS11__CK_OTP_PARAM* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_OTP_PARAM))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pValue) {
        Safefree(object->private.pValue);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pValue) {
        CK_BYTE_PTR pValue = 0;
        myNewxz(pValue, object->private.ulValueLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pValue) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pValue, pValue, object->private.ulValueLen, CK_BYTE);
        object->private.pValue = pValue;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_otp_param_DESTROY(Crypt__PKCS11__CK_OTP_PARAM* object) {
    if (object) {
        if (object->private.pValue) {
            Safefree(object->private.pValue);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_otp_param_get_type(Crypt__PKCS11__CK_OTP_PARAM* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.type);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_set_type(Crypt__PKCS11__CK_OTP_PARAM* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.type = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_get_pValue(Crypt__PKCS11__CK_OTP_PARAM* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pValue, object->private.ulValueLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_set_pValue(Crypt__PKCS11__CK_OTP_PARAM* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pValue) {
            Safefree(object->private.pValue);
            object->private.pValue = 0;
            object->private.ulValueLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pValue) {
        Safefree(object->private.pValue);
    }
    object->private.pValue = n;
    object->private.ulValueLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAMS* crypt_pkcs11_ck_otp_params_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_OTP_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_otp_params_toBytes(Crypt__PKCS11__CK_OTP_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_OTP_PARAMS));
}

CK_RV crypt_pkcs11_ck_otp_params_fromBytes(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_OTP_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pParams) {
        CK_ULONG ulCount;
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                Safefree(object->private.pParams[ulCount].pValue);
            }
        }
        Safefree(object->private.pParams);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pParams) {
        CK_OTP_PARAM_PTR params = 0;
        CK_ULONG ulCount;

        myNewxz(params, object->private.ulCount, CK_OTP_PARAM);
        /* uncoverable branch 0 */
        if (!params) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }

        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            params[ulCount].type = object->private.pParams[ulCount].type;
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                myNewxz(params[ulCount].pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
                /* uncoverable branch 0 */
                if (!params[ulCount].pValue) {
                    /* uncoverable block 0 */
                    __croak("memory allocation error");
                }
                Copy(object->private.pParams[ulCount].pValue, params[ulCount].pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
            }
        }
        object->private.pParams = params;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_otp_params_DESTROY(Crypt__PKCS11__CK_OTP_PARAMS* object) {
    if (object) {
        if (object->private.pParams) {
            CK_ULONG ulCount;
            for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
                /* uncoverable branch 1 */
                if (object->private.pParams[ulCount].pValue) {
                    Safefree(object->private.pParams[ulCount].pValue);
                }
            }
            Safefree(object->private.pParams);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_otp_params_get_pParams(Crypt__PKCS11__CK_OTP_PARAMS* object, AV* sv) {
    CK_ULONG ulCount;
    Crypt__PKCS11__CK_OTP_PARAM* param;
    SV* paramSV;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(object->private.ulCount)) {
        return CKR_OK;
    }

    for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
        param = 0;
        myNewxz(param, 1, Crypt__PKCS11__CK_OTP_PARAM);
        /* uncoverable branch 0 */
        if (!param) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.pParams[ulCount].type;
        /* uncoverable branch 1 */
        if (object->private.pParams[ulCount].pValue) {
            myNewxz(param->private.pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!param->private.pValue) {
                /* uncoverable begin */
                Safefree(param);
                return CKR_HOST_MEMORY;
                /* uncoverable end */
            }
            Copy(object->private.pParams[ulCount].pValue, param->private.pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
            param->private.ulValueLen = object->private.pParams[ulCount].ulValueLen;
        }

        paramSV = sv_setref_pv(newSV(0), "Crypt::PKCS11::CK_OTP_PARAMPtr", param);
        av_push(sv, paramSV);
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_params_set_pParams(Crypt__PKCS11__CK_OTP_PARAMS* object, AV* sv) {
    CK_ULONG ulCount;
    I32 key;
    SV** item;
    SV* entry;
    IV tmp;
    Crypt__PKCS11__CK_OTP_PARAM* param;
    CK_OTP_PARAM_PTR params = 0;
    CK_ULONG paramCount = 0;
    CK_RV rv = CKR_OK;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        item = av_fetch(sv, key, 0);

        /* uncoverable begin */
        if (!item || !*item || !SvROK(*item)
        /* uncoverable end */
            || !sv_derived_from(*item, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            return CKR_ARGUMENTS_BAD;
        }

        paramCount++;
    }

    myNewxz(params, paramCount, CK_OTP_PARAM);
    /* uncoverable branch 0 */
    if (!params) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        item = av_fetch(sv, key, 0);

        /* uncoverable begin */
        if (!item || !*item || !SvROK(*item)
            || !sv_derived_from(*item, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        tmp = SvIV((SV*)SvRV(*item));
        if (!(param = INT2PTR(Crypt__PKCS11__CK_OTP_PARAM*, tmp))) {
            rv = CKR_GENERAL_ERROR;
            break;
        }
        /* uncoverable end */

        params[key].type = param->private.type;
        /* uncoverable branch 1 */
        if (param->private.pValue) {
            myNewxz(params[key].pValue, param->private.ulValueLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!params[key].pValue) {
                /* uncoverable begin */
                rv = CKR_HOST_MEMORY;
                break;
                /* uncoverable end */
            }

            Copy(param->private.pValue, params[key].pValue, param->private.ulValueLen, CK_BYTE);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    /* uncoverable begin */
    if (rv != CKR_OK) {
        for (ulCount = 0; ulCount < paramCount; ulCount++) {
            if (params[ulCount].pValue) {
                Safefree(params[ulCount].pValue);
            }
        }
        Safefree(params);
        return rv;
    }
    /* uncoverable end */

    if (object->private.pParams) {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                Safefree(object->private.pParams[ulCount].pValue);
            }
        }
        Safefree(object->private.pParams);
    }
    object->private.pParams = params;
    object->private.ulCount = paramCount;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_params_get_ulCount(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulCount);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_params_set_ulCount(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* crypt_pkcs11_ck_otp_signature_info_new(const char* class) {
    Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_OTP_SIGNATURE_INFO);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_otp_signature_info_toBytes(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_OTP_SIGNATURE_INFO));
}

CK_RV crypt_pkcs11_ck_otp_signature_info_fromBytes(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_OTP_SIGNATURE_INFO))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pParams) {
        CK_ULONG ulCount;
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                Safefree(object->private.pParams[ulCount].pValue);
            }
        }
        Safefree(object->private.pParams);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pParams) {
        CK_OTP_PARAM_PTR params = 0;
        CK_ULONG ulCount;

        myNewxz(params, object->private.ulCount, CK_OTP_PARAM);
        /* uncoverable branch 0 */
        if (!params) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }

        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            params[ulCount].type = object->private.pParams[ulCount].type;
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                myNewxz(params[ulCount].pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
                /* uncoverable branch 0 */
                if (!params[ulCount].pValue) {
                    /* uncoverable block 0 */
                    __croak("memory allocation error");
                }
                Copy(object->private.pParams[ulCount].pValue, params[ulCount].pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
            }
        }
        object->private.pParams = params;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_otp_signature_info_DESTROY(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object) {
    if (object) {
        if (object->private.pParams) {
            CK_ULONG ulCount;
            for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
                /* uncoverable branch 1 */
                if (object->private.pParams[ulCount].pValue) {
                    Safefree(object->private.pParams[ulCount].pValue);
                }
            }
            Safefree(object->private.pParams);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_otp_signature_info_get_pParams(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, AV* sv) {
    CK_ULONG ulCount;
    Crypt__PKCS11__CK_OTP_PARAM* param;
    SV* paramSV;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(object->private.ulCount)) {
        return CKR_OK;
    }

    for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
        param = 0;
        myNewxz(param, 1, Crypt__PKCS11__CK_OTP_PARAM);
        /* uncoverable branch 0 */
        if (!param) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.pParams[ulCount].type;
        /* uncoverable branch 1 */
        if (object->private.pParams[ulCount].pValue) {
            myNewxz(param->private.pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!param->private.pValue) {
                /* uncoverable begin */
                Safefree(param);
                return CKR_HOST_MEMORY;
                /* uncoverable end */
            }
            Copy(object->private.pParams[ulCount].pValue, param->private.pValue, object->private.pParams[ulCount].ulValueLen, CK_BYTE);
            param->private.ulValueLen = object->private.pParams[ulCount].ulValueLen;
        }

        paramSV = sv_setref_pv(newSV(0), "Crypt::PKCS11::CK_OTP_PARAMPtr", param);
        av_push(sv, paramSV);
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_signature_info_set_pParams(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, AV* sv) {
    CK_ULONG ulCount;
    I32 key;
    SV** item;
    SV* entry;
    IV tmp;
    Crypt__PKCS11__CK_OTP_PARAM* param;
    CK_OTP_PARAM_PTR params = 0;
    CK_ULONG paramCount = 0;
    CK_RV rv = CKR_OK;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        item = av_fetch(sv, key, 0);

        /* uncoverable begin */
        if (!item || !*item || !SvROK(*item)
        /* uncoverable end */
            || !sv_derived_from(*item, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            return CKR_ARGUMENTS_BAD;
        }

        paramCount++;
    }

    myNewxz(params, paramCount, CK_OTP_PARAM);
    /* uncoverable branch 0 */
    if (!params) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        item = av_fetch(sv, key, 0);

        /* uncoverable begin */
        if (!item || !*item || !SvROK(*item)
            || !sv_derived_from(*item, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }

        tmp = SvIV((SV*)SvRV(*item));
        if (!(param = INT2PTR(Crypt__PKCS11__CK_OTP_PARAM*, tmp))) {
            rv = CKR_GENERAL_ERROR;
            break;
        }
        /* uncoverable end */

        params[key].type = param->private.type;
        /* uncoverable branch 1 */
        if (param->private.pValue) {
            myNewxz(params[key].pValue, param->private.ulValueLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!params[key].pValue) {
                /* uncoverable begin */
                rv = CKR_HOST_MEMORY;
                break;
                /* uncoverable end */
            }

            Copy(param->private.pValue, params[key].pValue, param->private.ulValueLen, CK_BYTE);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    /* uncoverable begin */
    if (rv != CKR_OK) {
        for (ulCount = 0; ulCount < paramCount; ulCount++) {
            if (params[ulCount].pValue) {
                Safefree(params[ulCount].pValue);
            }
        }
        Safefree(params);
        return rv;
    }
    /* uncoverable end */

    if (object->private.pParams) {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                Safefree(object->private.pParams[ulCount].pValue);
            }
        }
        Safefree(object->private.pParams);
    }
    object->private.pParams = params;
    object->private.ulCount = paramCount;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_signature_info_get_ulCount(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulCount);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_signature_info_set_ulCount(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_KIP_PARAMS* crypt_pkcs11_ck_kip_params_new(const char* class) {
    Crypt__PKCS11__CK_KIP_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_KIP_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        object->private.pMechanism = &(object->pMechanism);
    }
    return object;
}

SV* crypt_pkcs11_ck_kip_params_toBytes(Crypt__PKCS11__CK_KIP_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_KIP_PARAMS));
}

CK_RV crypt_pkcs11_ck_kip_params_fromBytes(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_KIP_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->pMechanism.pParameter) {
        Safefree(object->pMechanism.pParameter);
    }
    Zero(&(object->pMechanism), 1, CK_MECHANISM);
    if (object->private.pSeed) {
        Safefree(object->private.pSeed);
    }
    Copy(p, &(object->private), l, char);

    /* uncoverable branch 1 */
    if (object->private.pMechanism) {
        Copy(object->private.pMechanism, &(object->pMechanism), 1, CK_MECHANISM);
        if (object->pMechanism.pParameter) {
            CK_VOID_PTR pParameter = 0;
            myNewxz(pParameter, object->pMechanism.ulParameterLen, CK_BYTE);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            Copy(object->pMechanism.pParameter, pParameter, object->pMechanism.ulParameterLen, CK_BYTE);
            object->pMechanism.pParameter = pParameter;
        }
    }
    object->private.pMechanism = &(object->pMechanism);

    if (object->private.pSeed) {
        CK_BYTE_PTR pSeed = 0;
        myNewxz(pSeed, object->private.ulSeedLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pSeed) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pSeed, pSeed, object->private.ulSeedLen, CK_BYTE);
        object->private.pSeed = pSeed;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_kip_params_DESTROY(Crypt__PKCS11__CK_KIP_PARAMS* object) {
    if (object) {
        if (object->pMechanism.pParameter) {
            Safefree(object->pMechanism.pParameter);
        }
        if (object->private.pSeed) {
            Safefree(object->private.pSeed);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_kip_params_get_pMechanism(Crypt__PKCS11__CK_KIP_PARAMS* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->pMechanism.ulParameterLen) {
        myNewxz(pParameter, object->pMechanism.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(object->pMechanism.pParameter, pParameter, object->pMechanism.ulParameterLen, CK_BYTE);
    }

    if (sv->private.pParameter) {
        Safefree(sv->private.pParameter);
    }
    sv->private.mechanism = object->pMechanism.mechanism;
    sv->private.pParameter = pParameter;
    sv->private.ulParameterLen = object->pMechanism.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_pMechanism(Crypt__PKCS11__CK_KIP_PARAMS* object, Crypt__PKCS11__CK_MECHANISM* sv) {
    CK_VOID_PTR pParameter = NULL_PTR;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    if (sv->private.ulParameterLen) {
        myNewxz(pParameter, sv->private.ulParameterLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
    }

    if (pParameter) {
        Copy(sv->private.pParameter, pParameter, sv->private.ulParameterLen, CK_BYTE);
    }

    if (object->pMechanism.pParameter) {
        Safefree(object->pMechanism.pParameter);
    }
    object->pMechanism.mechanism = sv->private.mechanism;
    object->pMechanism.pParameter = pParameter;
    object->pMechanism.ulParameterLen = sv->private.ulParameterLen;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_get_hKey(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.hKey);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_hKey(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.hKey = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_get_pSeed(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pSeed, object->private.ulSeedLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_pSeed(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pSeed) {
            Safefree(object->private.pSeed);
            object->private.pSeed = 0;
            object->private.ulSeedLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pSeed) {
        Safefree(object->private.pSeed);
    }
    object->private.pSeed = n;
    object->private.ulSeedLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CTR_PARAMS* crypt_pkcs11_ck_aes_ctr_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CTR_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_AES_CTR_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_ctr_params_toBytes(Crypt__PKCS11__CK_AES_CTR_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_AES_CTR_PARAMS));
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_fromBytes(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_AES_CTR_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_aes_ctr_params_DESTROY(Crypt__PKCS11__CK_AES_CTR_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_get_ulCounterBits(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulCounterBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_set_ulCounterBits(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulCounterBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_get_cb(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.cb, 16 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_set_cb(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.cb, 16, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (16 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.cb, 16, CK_BYTE);

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_GCM_PARAMS* crypt_pkcs11_ck_aes_gcm_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_GCM_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_AES_GCM_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_gcm_params_toBytes(Crypt__PKCS11__CK_AES_GCM_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_AES_GCM_PARAMS));
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_fromBytes(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_AES_GCM_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pIv) {
        Safefree(object->private.pIv);
    }
    if (object->private.pAAD) {
        Safefree(object->private.pAAD);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pIv) {
        CK_BYTE_PTR pIv = 0;
        myNewxz(pIv, object->private.ulIvLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pIv) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pIv, pIv, object->private.ulIvLen, CK_BYTE);
        object->private.pIv = pIv;
    }
    if (object->private.pAAD) {
        CK_BYTE_PTR pAAD = 0;
        myNewxz(pAAD, object->private.ulAADLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pAAD) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pAAD, pAAD, object->private.ulAADLen, CK_BYTE);
        object->private.pAAD = pAAD;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aes_gcm_params_DESTROY(Crypt__PKCS11__CK_AES_GCM_PARAMS* object) {
    if (object) {
        if (object->private.pIv) {
            Safefree(object->private.pIv);
        }
        if (object->private.pAAD) {
            Safefree(object->private.pAAD);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_pIv(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pIv, object->private.ulIvLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_pIv(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pIv) {
            Safefree(object->private.pIv);
            object->private.pIv = 0;
            object->private.ulIvLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pIv) {
        Safefree(object->private.pIv);
    }
    object->private.pIv = n;
    object->private.ulIvLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_ulIvBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulIvBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_ulIvBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulIvBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_pAAD(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pAAD, object->private.ulAADLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_pAAD(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pAAD) {
            Safefree(object->private.pAAD);
            object->private.pAAD = 0;
            object->private.ulAADLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pAAD) {
        Safefree(object->private.pAAD);
    }
    object->private.pAAD = n;
    object->private.ulAADLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_ulTagBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulTagBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_ulTagBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulTagBits = SvUV(sv);

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CCM_PARAMS* crypt_pkcs11_ck_aes_ccm_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CCM_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_AES_CCM_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_ccm_params_toBytes(Crypt__PKCS11__CK_AES_CCM_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_AES_CCM_PARAMS));
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_fromBytes(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_AES_CCM_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pNonce) {
        Safefree(object->private.pNonce);
    }
    if (object->private.pAAD) {
        Safefree(object->private.pAAD);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pNonce) {
        CK_BYTE_PTR pNonce = 0;
        myNewxz(pNonce, object->private.ulNonceLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pNonce) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pNonce, pNonce, object->private.ulNonceLen, CK_BYTE);
        object->private.pNonce = pNonce;
    }
    if (object->private.pAAD) {
        CK_BYTE_PTR pAAD = 0;
        myNewxz(pAAD, object->private.ulAADLen, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pAAD) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pAAD, pAAD, object->private.ulAADLen, CK_BYTE);
        object->private.pAAD = pAAD;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aes_ccm_params_DESTROY(Crypt__PKCS11__CK_AES_CCM_PARAMS* object) {
    if (object) {
        if (object->private.pNonce) {
            Safefree(object->private.pNonce);
        }
        if (object->private.pAAD) {
            Safefree(object->private.pAAD);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_get_pNonce(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pNonce, object->private.ulNonceLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_set_pNonce(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pNonce) {
            Safefree(object->private.pNonce);
            object->private.pNonce = 0;
            object->private.ulNonceLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pNonce) {
        Safefree(object->private.pNonce);
    }
    object->private.pNonce = n;
    object->private.ulNonceLen = l;

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_get_pAAD(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pAAD, object->private.ulAADLen * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_set_pAAD(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pAAD) {
            Safefree(object->private.pAAD);
            object->private.pAAD = 0;
            object->private.ulAADLen = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pAAD) {
        Safefree(object->private.pAAD);
    }
    object->private.pAAD = n;
    object->private.ulAADLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* crypt_pkcs11_ck_camellia_ctr_params_new(const char* class) {
    Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_camellia_ctr_params_toBytes(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_CAMELLIA_CTR_PARAMS));
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_fromBytes(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_CAMELLIA_CTR_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, &(object->private), l, char);

    return CKR_OK;
}

void crypt_pkcs11_ck_camellia_ctr_params_DESTROY(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object) {
    if (object) {
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_get_ulCounterBits(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setuv(sv, object->private.ulCounterBits);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_set_ulCounterBits(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    if (!crypt_pkcs11_xs_SvUOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    object->private.ulCounterBits = SvUV(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_get_cb(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.cb, 16 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_set_cb(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.cb, 16, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (16 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.cb, 16, CK_BYTE);

    return CKR_OK;
}

Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS));
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_fromBytes(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pData) {
        CK_BYTE_PTR pData = 0;
        myNewxz(pData, object->private.length, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pData, pData, object->private.length, CK_BYTE);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            Safefree(object->private.pData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.iv, 16 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.iv, 16, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (16 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.iv, 16, CK_BYTE);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pData, object->private.length * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pData) {
            Safefree(object->private.pData);
            object->private.pData = 0;
            object->private.length = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_aria_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object = 0;
    myNewxz(object, 1, Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS);

    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aria_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (!object) {
        return 0;
    }

    return newSVpvn((const char*)&(object->private), sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS));
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_fromBytes(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l != sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    Copy(p, &(object->private), l, char);

    if (object->private.pData) {
        CK_BYTE_PTR pData = 0;
        myNewxz(pData, object->private.length, CK_BYTE);
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        Copy(object->private.pData, pData, object->private.length, CK_BYTE);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aria_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            Safefree(object->private.pData);
        }
        Safefree(object);
    }
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.iv, 16 * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    char* p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        Zero(object->private.iv, 16, CK_BYTE);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        /* uncoverable block 0 */
        return CKR_GENERAL_ERROR;
    }
    if (l != (16 * sizeof(CK_BYTE))) {
        return CKR_ARGUMENTS_BAD;
    }

    Copy(p, object->private.iv, 16, CK_BYTE);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);
    sv_setpvn(sv, object->private.pData, object->private.length * sizeof(CK_BYTE));
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n = 0;
    CK_BYTE_PTR p;
    STRLEN l;

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(sv);

    /* uncoverable branch 0 */
    if (!SvOK(sv)) {
        if (object->private.pData) {
            Safefree(object->private.pData);
            object->private.pData = 0;
            object->private.length = 0;
        }
        return CKR_OK;
    }

    if (!SvPOK(sv)
        || !(p = SvPVbyte(sv, l))
        || l < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    myNewxz(n, l, CK_BYTE);
    /* uncoverable branch 0 */
    if (!n) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    Copy(p, n, l, CK_BYTE);
    if (object->private.pData) {
        Safefree(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

