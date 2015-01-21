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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "crypt_pkcs11_struct.h"

#include <stdlib.h>
#include <string.h>

#ifdef TEST_DEVEL_COVER
int __test_devel_cover_calloc_always_fail = 0;
static void* __calloc(size_t nmemb, size_t size) {
    if (__test_devel_cover_calloc_always_fail) {
        return 0;
    }
    return calloc(nmemb, size);
}
#define calloc(a,b) __calloc(a,b)
#define __croak(x) return 0
/* uncoverable begin */
int crypt_pkcs11_struct_xs_test_devel_cover(void) {
    {
        Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT));
        if (!object) { return __LINE__; };
        if (!(object->private.pIVClient = calloc(1, 1))) { return __LINE__; }
        if (!(object->private.pIVServer = calloc(1, 1))) { return __LINE__; }
        crypt_pkcs11_ck_ssl3_key_mat_out_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS));
        if (!object) { return __LINE__; };
        if (!(object->pReturnedKeyMaterial.pIVClient = calloc(1, 1))) { return __LINE__; }
        if (!(object->pReturnedKeyMaterial.pIVServer = calloc(1, 1))) { return __LINE__; }
        crypt_pkcs11_ck_ssl3_key_mat_params_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT));
        if (!object) { return __LINE__; };
        if (!(object->private.pIV = calloc(1, 1))) { return __LINE__; }
        crypt_pkcs11_ck_wtls_key_mat_out_DESTROY(object);
    }
    {
        Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS));
        if (!object) { return __LINE__; };
        if (!(object->pReturnedKeyMaterial.pIV = calloc(1, 1))) { return __LINE__; }
        crypt_pkcs11_ck_wtls_key_mat_params_DESTROY(object);
    }
    return 0;
}
/* uncoverable end */
#else
#define __croak(x) croak(x)
#endif

extern int crypt_pkcs11_xs_SvUOK(SV* sv);

Crypt__PKCS11__CK_VERSION* crypt_pkcs11_ck_version_new(const char* class) {
    Crypt__PKCS11__CK_VERSION* object = calloc(1, sizeof(Crypt__PKCS11__CK_VERSION));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_version_DESTROY(Crypt__PKCS11__CK_VERSION* object) {
    if (object) {
        free(object);
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
    Crypt__PKCS11__CK_MECHANISM* object = calloc(1, sizeof(Crypt__PKCS11__CK_MECHANISM));
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
        free(object->private.pParameter);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pParameter) {
        CK_BYTE_PTR pParameter = calloc(object->private.ulParameterLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pParameter) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pParameter, object->private.pParameter, object->private.ulParameterLen);
        object->private.pParameter = pParameter;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_mechanism_DESTROY(Crypt__PKCS11__CK_MECHANISM* object) {
    if (object) {
        if (object->private.pParameter) {
            free(object->private.pParameter);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pParameter, object->private.ulParameterLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_mechanism_set_pParameter(Crypt__PKCS11__CK_MECHANISM* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pParameter);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pParameter) {
        free(object->private.pParameter);
    }
    object->private.pParameter = n;
    object->private.ulParameterLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* crypt_pkcs11_ck_rsa_pkcs_oaep_params_new(const char* class) {
    Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS));
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
        free(object->private.pSourceData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSourceData) {
        CK_BYTE_PTR pSourceData = calloc(object->private.ulSourceDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSourceData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSourceData, object->private.pSourceData, object->private.ulSourceDataLen);
        object->private.pSourceData = pSourceData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_rsa_pkcs_oaep_params_DESTROY(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object) {
    if (object) {
        if (object->private.pSourceData) {
            free(object->private.pSourceData);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSourceData, object->private.ulSourceDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_pSourceData(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSourceData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSourceData) {
        free(object->private.pSourceData);
    }
    object->private.pSourceData = n;
    object->private.ulSourceDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* crypt_pkcs11_ck_rsa_pkcs_pss_params_new(const char* class) {
    Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_rsa_pkcs_pss_params_DESTROY(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object) {
    if (object) {
        free(object);
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
    Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS));
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
        free(object->private.pSharedData);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSharedData) {
        CK_BYTE_PTR pSharedData = calloc(object->private.ulSharedDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSharedData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSharedData, object->private.pSharedData, object->private.ulSharedDataLen);
        object->private.pSharedData = pSharedData;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ecdh1_derive_params_DESTROY(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pSharedData) {
            free(object->private.pSharedData);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSharedData, object->private.ulSharedDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSharedData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSharedData) {
        free(object->private.pSharedData);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* crypt_pkcs11_ck_ecdh2_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS));
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
        free(object->private.pSharedData);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSharedData) {
        CK_BYTE_PTR pSharedData = calloc(object->private.ulSharedDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSharedData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSharedData, object->private.pSharedData, object->private.ulSharedDataLen);
        object->private.pSharedData = pSharedData;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = calloc(object->private.ulPublicDataLen2, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData2, object->private.pPublicData2, object->private.ulPublicDataLen2);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ecdh2_derive_params_DESTROY(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pSharedData) {
            free(object->private.pSharedData);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            free(object->private.pPublicData2);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSharedData, object->private.ulSharedDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSharedData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSharedData) {
        free(object->private.pSharedData);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
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
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData2);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
    }
    object->private.pPublicData2 = n;
    object->private.ulPublicDataLen2 = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* crypt_pkcs11_ck_ecmqv_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS));
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
        free(object->private.pSharedData);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSharedData) {
        CK_BYTE_PTR pSharedData = calloc(object->private.ulSharedDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSharedData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSharedData, object->private.pSharedData, object->private.ulSharedDataLen);
        object->private.pSharedData = pSharedData;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = calloc(object->private.ulPublicDataLen2, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData2, object->private.pPublicData2, object->private.ulPublicDataLen2);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ecmqv_derive_params_DESTROY(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pSharedData) {
            free(object->private.pSharedData);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            free(object->private.pPublicData2);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSharedData, object->private.ulSharedDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSharedData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSharedData) {
        free(object->private.pSharedData);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
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
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData2);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
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
    Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS));
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
        free(object->private.pOtherInfo);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pOtherInfo) {
        CK_BYTE_PTR pOtherInfo = calloc(object->private.ulOtherInfoLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOtherInfo) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOtherInfo, object->private.pOtherInfo, object->private.ulOtherInfoLen);
        object->private.pOtherInfo = pOtherInfo;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_x9_42_dh1_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pOtherInfo) {
            free(object->private.pOtherInfo);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pOtherInfo, object->private.ulOtherInfoLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOtherInfo);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOtherInfo) {
        free(object->private.pOtherInfo);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_dh2_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS));
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
        free(object->private.pOtherInfo);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pOtherInfo) {
        CK_BYTE_PTR pOtherInfo = calloc(object->private.ulOtherInfoLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOtherInfo) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOtherInfo, object->private.pOtherInfo, object->private.ulOtherInfoLen);
        object->private.pOtherInfo = pOtherInfo;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = calloc(object->private.ulPublicDataLen2, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData2, object->private.pPublicData2, object->private.ulPublicDataLen2);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_x9_42_dh2_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pOtherInfo) {
            free(object->private.pOtherInfo);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            free(object->private.pPublicData2);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pOtherInfo, object->private.ulOtherInfoLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOtherInfo);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOtherInfo) {
        free(object->private.pOtherInfo);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
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
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData2);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
    }
    object->private.pPublicData2 = n;
    object->private.ulPublicDataLen2 = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_mqv_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS));
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
        free(object->private.pOtherInfo);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pOtherInfo) {
        CK_BYTE_PTR pOtherInfo = calloc(object->private.ulOtherInfoLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOtherInfo) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOtherInfo, object->private.pOtherInfo, object->private.ulOtherInfoLen);
        object->private.pOtherInfo = pOtherInfo;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pPublicData2) {
        CK_BYTE_PTR pPublicData2 = calloc(object->private.ulPublicDataLen2, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData2) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData2, object->private.pPublicData2, object->private.ulPublicDataLen2);
        object->private.pPublicData2 = pPublicData2;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_x9_42_mqv_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pOtherInfo) {
            free(object->private.pOtherInfo);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        if (object->private.pPublicData2) {
            free(object->private.pPublicData2);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pOtherInfo, object->private.ulOtherInfoLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOtherInfo);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOtherInfo) {
        free(object->private.pOtherInfo);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
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
    sv_setpvn(sv, object->private.pPublicData2, object->private.ulPublicDataLen2);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData2);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData2) {
        free(object->private.pPublicData2);
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
    Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS));
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
        free(object->private.pRandomA);
    }
    if (object->private.pRandomB) {
        free(object->private.pRandomB);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pRandomA) {
        CK_BYTE_PTR pRandomA = calloc(object->private.ulRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pRandomA, object->private.pRandomA, object->private.ulRandomLen);
        object->private.pRandomA = pRandomA;
    }
    if (object->private.pRandomB) {
        CK_BYTE_PTR pRandomB = calloc(object->private.ulRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pRandomB) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pRandomB, object->private.pRandomB, object->private.ulRandomLen);
        object->private.pRandomB = pRandomB;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_kea_derive_params_DESTROY(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.pRandomA) {
            free(object->private.pRandomA);
        }
        if (object->private.pRandomB) {
            free(object->private.pRandomB);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pRandomA, object->private.ulRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pRandomA(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pRandomA);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pRandomA) {
        free(object->private.pRandomA);
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
    sv_setpvn(sv, object->private.pRandomB, object->private.ulRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pRandomB(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pRandomB);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pRandomB) {
        free(object->private.pRandomB);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pPublicData(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    object->private.pPublicData = n;
    object->private.ulPublicDataLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RC2_CBC_PARAMS* crypt_pkcs11_ck_rc2_cbc_params_new(const char* class) {
    Crypt__PKCS11__CK_RC2_CBC_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC2_CBC_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc2_cbc_params_DESTROY(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object) {
    if (object) {
        free(object);
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
        memset(object->private.iv, 0, 8 * sizeof(CK_BYTE));
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

    memcpy(object->private.iv, p, 8 * sizeof(CK_BYTE));

    return CKR_OK;
}

Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* crypt_pkcs11_ck_rc2_mac_general_params_new(const char* class) {
    Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc2_mac_general_params_DESTROY(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object) {
    if (object) {
        free(object);
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
    Crypt__PKCS11__CK_RC5_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC5_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc5_params_DESTROY(Crypt__PKCS11__CK_RC5_PARAMS* object) {
    if (object) {
        free(object);
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
    Crypt__PKCS11__CK_RC5_CBC_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC5_CBC_PARAMS));
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
        free(object->private.pIv);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pIv) {
        CK_BYTE_PTR pIv = calloc(object->private.ulIvLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pIv) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pIv, object->private.pIv, object->private.ulIvLen);
        object->private.pIv = pIv;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_rc5_cbc_params_DESTROY(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object) {
    if (object) {
        if (object->private.pIv) {
            free(object->private.pIv);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pIv, object->private.ulIvLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_pIv(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pIv);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pIv) {
        free(object->private.pIv);
    }
    object->private.pIv = n;
    object->private.ulIvLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* crypt_pkcs11_ck_rc5_mac_general_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_rc5_mac_general_params_DESTROY(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object) {
    if (object) {
        free(object);
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
    Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS));
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
        free(object->private.pData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pData) {
        CK_BYTE_PTR pData = calloc(object->private.length, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pData, object->private.pData, object->private.length);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_des_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            free(object->private.pData);
        }
        free(object);
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
        memset(object->private.iv, 0, 8 * sizeof(CK_BYTE));
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

    memcpy(object->private.iv, p, 8 * sizeof(CK_BYTE));

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
    sv_setpvn(sv, object->private.pData, object->private.length);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pData) {
        free(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_aes_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS));
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
        free(object->private.pData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pData) {
        CK_BYTE_PTR pData = calloc(object->private.length, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pData, object->private.pData, object->private.length);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aes_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            free(object->private.pData);
        }
        free(object);
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
        memset(object->private.iv, 0, 16 * sizeof(CK_BYTE));
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

    memcpy(object->private.iv, p, 16 * sizeof(CK_BYTE));

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
    sv_setpvn(sv, object->private.pData, object->private.length);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pData) {
        free(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* crypt_pkcs11_ck_skipjack_private_wrap_params_new(const char* class) {
    Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS));
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
        free(object->private.pPassword);
    }
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
    }
    if (object->private.pRandomA) {
        free(object->private.pRandomA);
    }
    if (object->private.pPrimeP) {
        free(object->private.pPrimeP);
    }
    if (object->private.pBaseG) {
        free(object->private.pBaseG);
    }
    if (object->private.pSubprimeQ) {
        free(object->private.pSubprimeQ);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pPassword) {
        CK_BYTE_PTR pPassword = calloc(object->private.ulPasswordLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPassword, object->private.pPassword, object->private.ulPasswordLen);
        object->private.pPassword = pPassword;
    }
    if (object->private.pPublicData) {
        CK_BYTE_PTR pPublicData = calloc(object->private.ulPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPublicData, object->private.pPublicData, object->private.ulPublicDataLen);
        object->private.pPublicData = pPublicData;
    }
    if (object->private.pRandomA) {
        CK_BYTE_PTR pRandomA = calloc(object->private.ulRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pRandomA, object->private.pRandomA, object->private.ulRandomLen);
        object->private.pRandomA = pRandomA;
    }
    if (object->private.pPrimeP) {
        CK_BYTE_PTR pPrimeP = calloc(object->private.ulPAndGLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPrimeP) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPrimeP, object->private.pPrimeP, object->private.ulPAndGLen);
        object->private.pPrimeP = pPrimeP;
    }
    if (object->private.pBaseG) {
        CK_BYTE_PTR pBaseG = calloc(object->private.ulPAndGLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pBaseG) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pBaseG, object->private.pBaseG, object->private.ulPAndGLen);
        object->private.pBaseG = pBaseG;
    }
    if (object->private.pSubprimeQ) {
        CK_BYTE_PTR pSubprimeQ = calloc(object->private.ulQLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSubprimeQ) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSubprimeQ, object->private.pSubprimeQ, object->private.ulQLen);
        object->private.pSubprimeQ = pSubprimeQ;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_skipjack_private_wrap_params_DESTROY(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object) {
    if (object) {
        if (object->private.pPassword) {
            free(object->private.pPassword);
        }
        if (object->private.pPublicData) {
            free(object->private.pPublicData);
        }
        if (object->private.pRandomA) {
            free(object->private.pRandomA);
        }
        if (object->private.pPrimeP) {
            free(object->private.pPrimeP);
        }
        if (object->private.pBaseG) {
            free(object->private.pBaseG);
        }
        if (object->private.pSubprimeQ) {
            free(object->private.pSubprimeQ);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pPassword, object->private.ulPasswordLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPassword(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPassword);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPassword) {
        free(object->private.pPassword);
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
    sv_setpvn(sv, object->private.pPublicData, object->private.ulPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPublicData(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPublicData) {
        free(object->private.pPublicData);
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
    sv_setpvn(sv, object->private.pRandomA, object->private.ulRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pRandomA(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pRandomA);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pRandomA) {
        free(object->private.pRandomA);
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
    sv_setpvn(sv, object->private.pPrimeP, object->private.ulPAndGLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPrimeP(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPrimeP);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPrimeP) {
        free(object->private.pPrimeP);
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
    sv_setpvn(sv, object->private.pBaseG, object->private.ulPAndGLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pBaseG(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pBaseG);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pBaseG) {
        free(object->private.pBaseG);
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
    sv_setpvn(sv, object->private.pSubprimeQ, object->private.ulQLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pSubprimeQ(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSubprimeQ);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSubprimeQ) {
        free(object->private.pSubprimeQ);
    }
    object->private.pSubprimeQ = n;
    object->private.ulQLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* crypt_pkcs11_ck_skipjack_relayx_params_new(const char* class) {
    Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS));
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
        free(object->private.pOldWrappedX);
    }
    if (object->private.pOldPassword) {
        free(object->private.pOldPassword);
    }
    if (object->private.pOldPublicData) {
        free(object->private.pOldPublicData);
    }
    if (object->private.pOldRandomA) {
        free(object->private.pOldRandomA);
    }
    if (object->private.pNewPassword) {
        free(object->private.pNewPassword);
    }
    if (object->private.pNewPublicData) {
        free(object->private.pNewPublicData);
    }
    if (object->private.pNewRandomA) {
        free(object->private.pNewRandomA);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pOldWrappedX) {
        CK_BYTE_PTR pOldWrappedX = calloc(object->private.ulOldWrappedXLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOldWrappedX) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOldWrappedX, object->private.pOldWrappedX, object->private.ulOldWrappedXLen);
        object->private.pOldWrappedX = pOldWrappedX;
    }
    if (object->private.pOldPassword) {
        CK_BYTE_PTR pOldPassword = calloc(object->private.ulOldPasswordLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOldPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOldPassword, object->private.pOldPassword, object->private.ulOldPasswordLen);
        object->private.pOldPassword = pOldPassword;
    }
    if (object->private.pOldPublicData) {
        CK_BYTE_PTR pOldPublicData = calloc(object->private.ulOldPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOldPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOldPublicData, object->private.pOldPublicData, object->private.ulOldPublicDataLen);
        object->private.pOldPublicData = pOldPublicData;
    }
    if (object->private.pOldRandomA) {
        CK_BYTE_PTR pOldRandomA = calloc(object->private.ulOldRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOldRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOldRandomA, object->private.pOldRandomA, object->private.ulOldRandomLen);
        object->private.pOldRandomA = pOldRandomA;
    }
    if (object->private.pNewPassword) {
        CK_BYTE_PTR pNewPassword = calloc(object->private.ulNewPasswordLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pNewPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pNewPassword, object->private.pNewPassword, object->private.ulNewPasswordLen);
        object->private.pNewPassword = pNewPassword;
    }
    if (object->private.pNewPublicData) {
        CK_BYTE_PTR pNewPublicData = calloc(object->private.ulNewPublicDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pNewPublicData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pNewPublicData, object->private.pNewPublicData, object->private.ulNewPublicDataLen);
        object->private.pNewPublicData = pNewPublicData;
    }
    if (object->private.pNewRandomA) {
        CK_BYTE_PTR pNewRandomA = calloc(object->private.ulNewRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pNewRandomA) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pNewRandomA, object->private.pNewRandomA, object->private.ulNewRandomLen);
        object->private.pNewRandomA = pNewRandomA;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_skipjack_relayx_params_DESTROY(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object) {
    if (object) {
        if (object->private.pOldWrappedX) {
            free(object->private.pOldWrappedX);
        }
        if (object->private.pOldPassword) {
            free(object->private.pOldPassword);
        }
        if (object->private.pOldPublicData) {
            free(object->private.pOldPublicData);
        }
        if (object->private.pOldRandomA) {
            free(object->private.pOldRandomA);
        }
        if (object->private.pNewPassword) {
            free(object->private.pNewPassword);
        }
        if (object->private.pNewPublicData) {
            free(object->private.pNewPublicData);
        }
        if (object->private.pNewRandomA) {
            free(object->private.pNewRandomA);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pOldWrappedX, object->private.ulOldWrappedXLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldWrappedX(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOldWrappedX);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOldWrappedX) {
        free(object->private.pOldWrappedX);
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
    sv_setpvn(sv, object->private.pOldPassword, object->private.ulOldPasswordLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOldPassword);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOldPassword) {
        free(object->private.pOldPassword);
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
    sv_setpvn(sv, object->private.pOldPublicData, object->private.ulOldPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOldPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOldPublicData) {
        free(object->private.pOldPublicData);
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
    sv_setpvn(sv, object->private.pOldRandomA, object->private.ulOldRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pOldRandomA);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pOldRandomA) {
        free(object->private.pOldRandomA);
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
    sv_setpvn(sv, object->private.pNewPassword, object->private.ulNewPasswordLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pNewPassword);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pNewPassword) {
        free(object->private.pNewPassword);
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
    sv_setpvn(sv, object->private.pNewPublicData, object->private.ulNewPublicDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pNewPublicData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pNewPublicData) {
        free(object->private.pNewPublicData);
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
    sv_setpvn(sv, object->private.pNewRandomA, object->private.ulNewRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pNewRandomA);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pNewRandomA) {
        free(object->private.pNewRandomA);
    }
    object->private.pNewRandomA = n;
    object->private.ulNewRandomLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_PBE_PARAMS* crypt_pkcs11_ck_pbe_params_new(const char* class) {
    Crypt__PKCS11__CK_PBE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_PBE_PARAMS));
    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        /* uncoverable branch 1 */
        if (!(object->private.pInitVector = calloc(8, sizeof(CK_BYTE)))) {
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
        free(object->private.pInitVector);
    }
    if (object->private.pPassword) {
        free(object->private.pPassword);
    }
    if (object->private.pSalt) {
        free(object->private.pSalt);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pInitVector) {
        CK_BYTE_PTR pInitVector = calloc(8, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pInitVector) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pInitVector, object->private.pInitVector, 8 * sizeof(CK_BYTE));
        object->private.pInitVector = pInitVector;
    }
    else {
        /* uncoverable branch 1 */
        if (!(object->private.pInitVector = calloc(8, sizeof(CK_BYTE)))) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
    }
    if (object->private.pPassword) {
        CK_CHAR_PTR pPassword = calloc(object->private.ulPasswordLen, sizeof(CK_CHAR));
        /* uncoverable branch 0 */
        if (!pPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPassword, object->private.pPassword, object->private.ulPasswordLen);
        object->private.pPassword = pPassword;
    }
    if (object->private.pSalt) {
        CK_BYTE_PTR pSalt = calloc(object->private.ulSaltLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSalt) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSalt, object->private.pSalt, object->private.ulSaltLen);
        object->private.pSalt = pSalt;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_pbe_params_DESTROY(Crypt__PKCS11__CK_PBE_PARAMS* object) {
    if (object) {
        /* uncoverable branch 1 */
        if (object->private.pInitVector) {
            free(object->private.pInitVector);
        }
        if (object->private.pPassword) {
            free(object->private.pPassword);
        }
        if (object->private.pSalt) {
            free(object->private.pSalt);
        }
        free(object);
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
        memset(object->private.pInitVector, 0, 8 * sizeof(CK_BYTE));
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

    memcpy(object->private.pInitVector, p, 8 * sizeof(CK_BYTE));

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
    sv_setpvn(sv, object->private.pPassword, object->private.ulPasswordLen);
    sv_utf8_upgrade_nomg(sv);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pPassword(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    CK_CHAR_PTR n;
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
            free(object->private.pPassword);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPassword) {
        free(object->private.pPassword);
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
    sv_setpvn(sv, object->private.pSalt, object->private.ulSaltLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pSalt(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSalt);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSalt) {
        free(object->private.pSalt);
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
    Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS));
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
        free(object->private.pX);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pX) {
        CK_BYTE_PTR pX = calloc(object->private.ulXLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pX) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pX, object->private.pX, object->private.ulXLen);
        object->private.pX = pX;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_key_wrap_set_oaep_params_DESTROY(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object) {
    if (object) {
        if (object->private.pX) {
            free(object->private.pX);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pX, object->private.ulXLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_set_pX(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pX);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pX) {
        free(object->private.pX);
    }
    object->private.pX = n;
    object->private.ulXLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_RANDOM_DATA* crypt_pkcs11_ck_ssl3_random_data_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_RANDOM_DATA));
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
        free(object->private.pClientRandom);
    }
    if (object->private.pServerRandom) {
        free(object->private.pServerRandom);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pClientRandom) {
        CK_BYTE_PTR pClientRandom = calloc(object->private.ulClientRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pClientRandom, object->private.pClientRandom, object->private.ulClientRandomLen);
        object->private.pClientRandom = pClientRandom;
    }
    if (object->private.pServerRandom) {
        CK_BYTE_PTR pServerRandom = calloc(object->private.ulServerRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pServerRandom, object->private.pServerRandom, object->private.ulServerRandomLen);
        object->private.pServerRandom = pServerRandom;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_ssl3_random_data_DESTROY(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object) {
    if (object) {
        if (object->private.pClientRandom) {
            free(object->private.pClientRandom);
        }
        if (object->private.pServerRandom) {
            free(object->private.pServerRandom);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pClientRandom, object->private.ulClientRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_set_pClientRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pClientRandom);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pClientRandom) {
        free(object->private.pClientRandom);
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
    sv_setpvn(sv, object->private.pServerRandom, object->private.ulServerRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_set_pServerRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pServerRandom);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pServerRandom) {
        free(object->private.pServerRandom);
    }
    object->private.pServerRandom = n;
    object->private.ulServerRandomLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* crypt_pkcs11_ck_ssl3_master_key_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS));
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
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
    }
    memset(object->private.pVersion, 0, sizeof(CK_VERSION));

    memcpy(&(object->private), p, l);

    if (object->private.RandomInfo.pClientRandom) {
        CK_BYTE_PTR pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pClientRandom, object->private.RandomInfo.pClientRandom, object->private.RandomInfo.ulClientRandomLen);
        object->private.RandomInfo.pClientRandom = pClientRandom;
    }
    if (object->private.RandomInfo.pServerRandom) {
        CK_BYTE_PTR pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pServerRandom, object->private.RandomInfo.pServerRandom, object->private.RandomInfo.ulServerRandomLen);
        object->private.RandomInfo.pServerRandom = pServerRandom;
    }
    /* uncoverable branch 1 */
    if (object->private.pVersion) {
        memcpy(&(object->pVersion), object->private.pVersion, sizeof(CK_VERSION));
    }
    object->private.pVersion = &(object->pVersion);

    return CKR_OK;
}

void crypt_pkcs11_ck_ssl3_master_key_derive_params_DESTROY(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.RandomInfo.pClientRandom) {
            free(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            free(object->private.RandomInfo.pServerRandom);
        }
        free(object);
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

    if (object->private.RandomInfo.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, object->private.RandomInfo.pClientRandom, object->private.RandomInfo.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, object->private.RandomInfo.pServerRandom, object->private.RandomInfo.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (sv->private.pClientRandom) {
        free(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        free(sv->private.pServerRandom);
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

    if (sv->private.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, sv->private.pClientRandom, sv->private.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, sv->private.pServerRandom, sv->private.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (object->private.RandomInfo.pClientRandom) {
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
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
    Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT));
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
            free(object->private.pIVClient);
        }
        if (object->private.pIVServer) {
            free(object->private.pIVServer);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pIVClient, object->ulIVClient);
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
    sv_setpvn(sv, object->private.pIVServer, object->ulIVServer);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVServer(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* crypt_pkcs11_ck_ssl3_key_mat_params_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS));
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
            free(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            free(object->private.RandomInfo.pServerRandom);
        }
        if (object->pReturnedKeyMaterial.pIVClient) {
            free(object->pReturnedKeyMaterial.pIVClient);
        }
        if (object->pReturnedKeyMaterial.pIVServer) {
            free(object->pReturnedKeyMaterial.pIVServer);
        }
        free(object);
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

    if (object->private.RandomInfo.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, object->private.RandomInfo.pClientRandom, object->private.RandomInfo.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, object->private.RandomInfo.pServerRandom, object->private.RandomInfo.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (sv->private.pClientRandom) {
        free(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        free(sv->private.pServerRandom);
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

    if (sv->private.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, sv->private.pClientRandom, sv->private.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, sv->private.pServerRandom, sv->private.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (object->private.RandomInfo.pClientRandom) {
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
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

    if (object->private.ulIVSizeInBits
        /* uncoverable branch 1 */
        && !(pIVClient = calloc(object->private.ulIVSizeInBits / 8, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (object->private.ulIVSizeInBits
        /* uncoverable branch 1 */
        && !(pIVServer = calloc(object->private.ulIVSizeInBits / 8, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pIVClient);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    /* uncoverable branch 2 */
    if (pIVClient && object->pReturnedKeyMaterial.pIVClient) {
        /* uncoverable block 0 */
        memcpy(pIVClient, object->pReturnedKeyMaterial.pIVClient, (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE));
    }
    /* uncoverable branch 2 */
    if (pIVServer && object->pReturnedKeyMaterial.pIVServer) {
        /* uncoverable block 0 */
        memcpy(pIVServer, object->pReturnedKeyMaterial.pIVServer, (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE));
    }

    if (sv->private.pIVClient) {
        free(sv->private.pIVClient);
    }
    if (sv->private.pIVServer) {
        free(sv->private.pIVServer);
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
    Crypt__PKCS11__CK_TLS_PRF_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_TLS_PRF_PARAMS));
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
        free(object->private.pSeed);
    }
    if (object->private.pLabel) {
        free(object->private.pLabel);
    }
    if (object->private.pOutput) {
        free(object->private.pOutput);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSeed) {
        CK_BYTE_PTR pSeed = calloc(object->private.ulSeedLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSeed) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSeed, object->private.pSeed, object->private.ulSeedLen);
        object->private.pSeed = pSeed;
    }
    if (object->private.pLabel) {
        CK_BYTE_PTR pLabel = calloc(object->private.ulLabelLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pLabel) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pLabel, object->private.pLabel, object->private.ulLabelLen);
        object->private.pLabel = pLabel;
    }
    if (object->private.pulOutputLen) {
        object->pulOutputLen = *(object->private.pulOutputLen);
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    if (object->private.pOutput) {
        CK_BYTE_PTR pOutput = calloc(object->pulOutputLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOutput) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOutput, object->private.pOutput, object->pulOutputLen);
        object->private.pOutput = pOutput;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_tls_prf_params_DESTROY(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object) {
    if (object) {
        if (object->private.pSeed) {
            free(object->private.pSeed);
        }
        if (object->private.pLabel) {
            free(object->private.pLabel);
        }
        if (object->private.pOutput) {
            free(object->private.pOutput);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSeed, object->private.ulSeedLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pSeed(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSeed);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSeed) {
        free(object->private.pSeed);
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
    sv_setpvn(sv, object->private.pLabel, object->private.ulLabelLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pLabel(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pLabel);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pLabel) {
        free(object->private.pLabel);
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
            free(object->private.pOutput);
        }

        /* uncoverable branch 1 */
        if (!(object->private.pOutput = calloc(1, object->pulOutputLen))) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.pOutput && object->pulOutputLen) {
        sv_setpvn(sv, object->private.pOutput, object->pulOutputLen);
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
            free(object->private.pOutput);
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
        free(object->private.pOutput);
    }

    /* uncoverable branch 1 */
    if (!(object->private.pOutput = calloc(1, l))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    object->pulOutputLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_RANDOM_DATA* crypt_pkcs11_ck_wtls_random_data_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_RANDOM_DATA));
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
        free(object->private.pClientRandom);
    }
    if (object->private.pServerRandom) {
        free(object->private.pServerRandom);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pClientRandom) {
        CK_BYTE_PTR pClientRandom = calloc(object->private.ulClientRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pClientRandom, object->private.pClientRandom, object->private.ulClientRandomLen);
        object->private.pClientRandom = pClientRandom;
    }
    if (object->private.pServerRandom) {
        CK_BYTE_PTR pServerRandom = calloc(object->private.ulServerRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pServerRandom, object->private.pServerRandom, object->private.ulServerRandomLen);
        object->private.pServerRandom = pServerRandom;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_wtls_random_data_DESTROY(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object) {
    if (object) {
        if (object->private.pClientRandom) {
            free(object->private.pClientRandom);
        }
        if (object->private.pServerRandom) {
            free(object->private.pServerRandom);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pClientRandom, object->private.ulClientRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_set_pClientRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pClientRandom);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pClientRandom) {
        free(object->private.pClientRandom);
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
    sv_setpvn(sv, object->private.pServerRandom, object->private.ulServerRandomLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_set_pServerRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pServerRandom);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pServerRandom) {
        free(object->private.pServerRandom);
    }
    object->private.pServerRandom = n;
    object->private.ulServerRandomLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* crypt_pkcs11_ck_wtls_master_key_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS));
    if (!object) {
        /* uncoverable block 0 */
        __croak("memory allocation error");
    }
    else {
        /* uncoverable branch 1 */
        if (!(object->private.pVersion = calloc(1, sizeof(CK_BYTE)))) {
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
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
    }
    /* uncoverable branch 1 */
    if (object->private.pVersion) {
        free(object->private.pVersion);
    }
    memcpy(&(object->private), p, l);

    if (object->private.RandomInfo.pClientRandom) {
        CK_BYTE_PTR pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pClientRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pClientRandom, object->private.RandomInfo.pClientRandom, object->private.RandomInfo.ulClientRandomLen);
        object->private.RandomInfo.pClientRandom = pClientRandom;
    }
    if (object->private.RandomInfo.pServerRandom) {
        CK_BYTE_PTR pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pServerRandom) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pServerRandom, object->private.RandomInfo.pServerRandom, object->private.RandomInfo.ulServerRandomLen);
        object->private.RandomInfo.pServerRandom = pServerRandom;
    }
    /* uncoverable branch 1 */
    if (object->private.pVersion) {
        CK_BYTE_PTR pVersion = calloc(1, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pVersion) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pVersion, object->private.pVersion, 1 * sizeof(CK_BYTE));
        object->private.pVersion = pVersion;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_wtls_master_key_derive_params_DESTROY(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object) {
    if (object) {
        if (object->private.RandomInfo.pClientRandom) {
            free(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            free(object->private.RandomInfo.pServerRandom);
        }
        /* uncoverable branch 1 */
        if (object->private.pVersion) {
            free(object->private.pVersion);
        }
        free(object);
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

    if (object->private.RandomInfo.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, object->private.RandomInfo.pClientRandom, object->private.RandomInfo.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, object->private.RandomInfo.pServerRandom, object->private.RandomInfo.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (sv->private.pClientRandom) {
        free(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        free(sv->private.pServerRandom);
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

    if (sv->private.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, sv->private.pClientRandom, sv->private.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, sv->private.pServerRandom, sv->private.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (object->private.RandomInfo.pClientRandom) {
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
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
    Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_PRF_PARAMS));
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
        free(object->private.pSeed);
    }
    if (object->private.pLabel) {
        free(object->private.pLabel);
    }
    if (object->private.pOutput) {
        free(object->private.pOutput);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSeed) {
        CK_BYTE_PTR pSeed = calloc(object->private.ulSeedLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSeed) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSeed, object->private.pSeed, object->private.ulSeedLen);
        object->private.pSeed = pSeed;
    }
    if (object->private.pLabel) {
        CK_BYTE_PTR pLabel = calloc(object->private.ulLabelLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pLabel) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pLabel, object->private.pLabel, object->private.ulLabelLen);
        object->private.pLabel = pLabel;
    }
    if (object->private.pulOutputLen) {
        object->pulOutputLen = *(object->private.pulOutputLen);
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    if (object->private.pOutput) {
        CK_BYTE_PTR pOutput = calloc(object->pulOutputLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pOutput) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pOutput, object->private.pOutput, object->pulOutputLen);
        object->private.pOutput = pOutput;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_wtls_prf_params_DESTROY(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object) {
    if (object) {
        if (object->private.pSeed) {
            free(object->private.pSeed);
        }
        if (object->private.pLabel) {
            free(object->private.pLabel);
        }
        if (object->private.pOutput) {
            free(object->private.pOutput);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSeed, object->private.ulSeedLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pSeed(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSeed);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSeed) {
        free(object->private.pSeed);
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
    sv_setpvn(sv, object->private.pLabel, object->private.ulLabelLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pLabel(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pLabel);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pLabel) {
        free(object->private.pLabel);
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
            free(object->private.pOutput);
        }

        /* uncoverable branch 1 */
        if (!(object->private.pOutput = calloc(1, object->pulOutputLen))) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.pOutput && object->pulOutputLen) {
        sv_setpvn(sv, object->private.pOutput, object->pulOutputLen);
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
            free(object->private.pOutput);
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
        free(object->private.pOutput);
    }

    /* uncoverable branch 1 */
    if (!(object->private.pOutput = calloc(1, l))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    object->pulOutputLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* crypt_pkcs11_ck_wtls_key_mat_out_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT));
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
            free(object->private.pIV);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pIV, object->ulIV);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_pIV(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
    return CKR_FUNCTION_NOT_SUPPORTED;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* crypt_pkcs11_ck_wtls_key_mat_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS));
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
            free(object->private.RandomInfo.pClientRandom);
        }
        if (object->private.RandomInfo.pServerRandom) {
            free(object->private.RandomInfo.pServerRandom);
        }
        if (object->pReturnedKeyMaterial.pIV) {
            free(object->pReturnedKeyMaterial.pIV);
        }
        free(object);
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

    if (object->private.RandomInfo.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, object->private.RandomInfo.pClientRandom, object->private.RandomInfo.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, object->private.RandomInfo.pServerRandom, object->private.RandomInfo.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (sv->private.pClientRandom) {
        free(sv->private.pClientRandom);
    }
    if (sv->private.pServerRandom) {
        free(sv->private.pServerRandom);
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

    if (sv->private.pClientRandom
        /* uncoverable branch 1 */
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        /* uncoverable branch 1 */
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        /* uncoverable begin */
        free(pClientRandom);
        return CKR_HOST_MEMORY;
        /* uncoverable end */
    }

    if (pClientRandom) {
        memcpy(pClientRandom, sv->private.pClientRandom, sv->private.ulClientRandomLen * sizeof(CK_BYTE));
    }
    if (pServerRandom) {
        memcpy(pServerRandom, sv->private.pServerRandom, sv->private.ulServerRandomLen * sizeof(CK_BYTE));
    }

    if (object->private.RandomInfo.pClientRandom) {
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
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

    if (object->private.ulIVSizeInBits
        /* uncoverable branch 1 */
        && !(pIV = calloc(object->private.ulIVSizeInBits / 8, sizeof(CK_BYTE))))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    /* uncoverable branch 2 */
    if (pIV && object->pReturnedKeyMaterial.pIV) {
        /* uncoverable block 0 */
        memcpy(pIV, object->pReturnedKeyMaterial.pIV, (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE));
    }

    if (sv->private.pIV) {
        free(sv->private.pIV);
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
    Crypt__PKCS11__CK_CMS_SIG_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_CMS_SIG_PARAMS));
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
        free(object->pSigningMechanism.pParameter);
    }
    memset(&(object->pSigningMechanism), 0, sizeof(CK_MECHANISM));
    if (object->pDigestMechanism.pParameter) {
        free(object->pDigestMechanism.pParameter);
    }
    memset(&(object->pDigestMechanism), 0, sizeof(CK_MECHANISM));
    if (object->private.pContentType) {
        free(object->private.pContentType);
    }
    if (object->private.pRequestedAttributes) {
        free(object->private.pRequestedAttributes);
    }
    if (object->private.pRequiredAttributes) {
        free(object->private.pRequiredAttributes);
    }
    memcpy(&(object->private), p, l);

    /* uncoverable branch 1 */
    if (object->private.pSigningMechanism) {
        memcpy(&(object->pSigningMechanism), object->private.pSigningMechanism, sizeof(CK_MECHANISM));
        if (object->pSigningMechanism.pParameter) {
            CK_VOID_PTR pParameter = calloc(object->pSigningMechanism.ulParameterLen, 1);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            memcpy(pParameter, object->pSigningMechanism.pParameter, object->pSigningMechanism.ulParameterLen);
            object->pSigningMechanism.pParameter = pParameter;
        }
    }
    object->private.pSigningMechanism = &(object->pSigningMechanism);

    /* uncoverable branch 1 */
    if (object->private.pDigestMechanism) {
        memcpy(&(object->pDigestMechanism), object->private.pDigestMechanism, sizeof(CK_MECHANISM));
        if (object->pDigestMechanism.pParameter) {
            CK_VOID_PTR pParameter = calloc(object->pDigestMechanism.ulParameterLen, 1);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            memcpy(pParameter, object->pDigestMechanism.pParameter, object->pDigestMechanism.ulParameterLen);
            object->pDigestMechanism.pParameter = pParameter;
        }
    }
    object->private.pDigestMechanism = &(object->pDigestMechanism);

    if (object->private.pContentType) {
        CK_CHAR_PTR pContentType = strdup(object->private.pContentType);
        /* uncoverable branch 0 */
        if (!pContentType) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        object->private.pContentType = pContentType;
    }
    if (object->private.pRequestedAttributes) {
        CK_BYTE_PTR pRequestedAttributes = calloc(object->private.ulRequestedAttributesLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pRequestedAttributes) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pRequestedAttributes, object->private.pRequestedAttributes, object->private.ulRequestedAttributesLen);
        object->private.pRequestedAttributes = pRequestedAttributes;
    }
    if (object->private.pRequiredAttributes) {
        CK_BYTE_PTR pRequiredAttributes = calloc(object->private.ulRequiredAttributesLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pRequiredAttributes) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pRequiredAttributes, object->private.pRequiredAttributes, object->private.ulRequiredAttributesLen);
        object->private.pRequiredAttributes = pRequiredAttributes;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_cms_sig_params_DESTROY(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object) {
    if (object) {
        if (object->pSigningMechanism.pParameter) {
            free(object->pSigningMechanism.pParameter);
        }
        if (object->pDigestMechanism.pParameter) {
            free(object->pDigestMechanism.pParameter);
        }
        if (object->private.pContentType) {
            free(object->private.pContentType);
        }
        if (object->private.pRequestedAttributes) {
            free(object->private.pRequestedAttributes);
        }
        if (object->private.pRequiredAttributes) {
            free(object->private.pRequiredAttributes);
        }
        free(object);
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

    if (object->pSigningMechanism.ulParameterLen
        /* uncoverable branch 1 */
        && !(pParameter = calloc(1, object->pSigningMechanism.ulParameterLen)))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    if (pParameter) {
        memcpy(pParameter, object->pSigningMechanism.pParameter, object->pSigningMechanism.ulParameterLen);
    }

    if (sv->private.pParameter) {
        free(sv->private.pParameter);
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

    if (sv->private.ulParameterLen
        /* uncoverable branch 1 */
        && !(pParameter = calloc(1, sv->private.ulParameterLen)))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    if (pParameter) {
        memcpy(pParameter, sv->private.pParameter, sv->private.ulParameterLen);
    }

    if (object->pSigningMechanism.pParameter) {
        free(object->pSigningMechanism.pParameter);
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

    if (object->pDigestMechanism.ulParameterLen
        /* uncoverable branch 1 */
        && !(pParameter = calloc(1, object->pDigestMechanism.ulParameterLen)))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    if (pParameter) {
        memcpy(pParameter, object->pDigestMechanism.pParameter, object->pDigestMechanism.ulParameterLen);
    }

    if (sv->private.pParameter) {
        free(sv->private.pParameter);
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

    if (sv->private.ulParameterLen
        /* uncoverable branch 1 */
        && !(pParameter = calloc(1, sv->private.ulParameterLen)))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    if (pParameter) {
        memcpy(pParameter, sv->private.pParameter, sv->private.ulParameterLen);
    }

    if (object->pDigestMechanism.pParameter) {
        free(object->pDigestMechanism.pParameter);
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
    CK_CHAR_PTR n;
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
            free(object->private.pContentType);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pContentType) {
        free(object->private.pContentType);
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
    sv_setpvn(sv, object->private.pRequestedAttributes, object->private.ulRequestedAttributesLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pRequestedAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pRequestedAttributes);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pRequestedAttributes) {
        free(object->private.pRequestedAttributes);
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
    sv_setpvn(sv, object->private.pRequiredAttributes, object->private.ulRequiredAttributesLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pRequiredAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pRequiredAttributes);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pRequiredAttributes) {
        free(object->private.pRequiredAttributes);
    }
    object->private.pRequiredAttributes = n;
    object->private.ulRequiredAttributesLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* crypt_pkcs11_ck_key_derivation_string_data_new(const char* class) {
    Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA));
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
        free(object->private.pData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pData) {
        CK_BYTE_PTR pData = calloc(object->private.ulLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pData, object->private.pData, object->private.ulLen);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_key_derivation_string_data_DESTROY(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object) {
    if (object) {
        if (object->private.pData) {
            free(object->private.pData);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pData, object->private.ulLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_set_pData(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pData) {
        free(object->private.pData);
    }
    object->private.pData = n;
    object->private.ulLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* crypt_pkcs11_ck_pkcs5_pbkd2_params_new(const char* class) {
    Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS));
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
        free(object->private.pSaltSourceData);
    }
    if (object->private.pPrfData) {
        free(object->private.pPrfData);
    }
    if (object->private.pPassword) {
        free(object->private.pPassword);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pSaltSourceData) {
        CK_BYTE_PTR pSaltSourceData = calloc(object->private.ulSaltSourceDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSaltSourceData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSaltSourceData, object->private.pSaltSourceData, object->private.ulSaltSourceDataLen);
        object->private.pSaltSourceData = pSaltSourceData;
    }
    if (object->private.pPrfData) {
        CK_BYTE_PTR pPrfData = calloc(object->private.ulPrfDataLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pPrfData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPrfData, object->private.pPrfData, object->private.ulPrfDataLen);
        object->private.pPrfData = pPrfData;
    }
    if (object->private.ulPasswordLen) {
        object->ulPasswordLen = *(object->private.ulPasswordLen);
    }
    object->private.ulPasswordLen = &(object->ulPasswordLen);
    if (object->private.pPassword) {
        CK_CHAR_PTR pPassword = calloc(object->ulPasswordLen, sizeof(CK_CHAR));
        /* uncoverable branch 0 */
        if (!pPassword) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pPassword, object->private.pPassword, object->ulPasswordLen);
        object->private.pPassword = pPassword;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_pkcs5_pbkd2_params_DESTROY(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object) {
    if (object) {
        if (object->private.pSaltSourceData) {
            free(object->private.pSaltSourceData);
        }
        if (object->private.pPrfData) {
            free(object->private.pPrfData);
        }
        if (object->private.pPassword) {
            free(object->private.pPassword);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pSaltSourceData, object->private.ulSaltSourceDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pSaltSourceData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSaltSourceData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSaltSourceData) {
        free(object->private.pSaltSourceData);
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
    sv_setpvn(sv, object->private.pPrfData, object->private.ulPrfDataLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPrfData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pPrfData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPrfData) {
        free(object->private.pPrfData);
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
            free(object->private.pPassword);
        }

        /* uncoverable branch 1 */
        if (!(object->private.pPassword = calloc(1, object->ulPasswordLen))) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

    /* uncoverable branch 3 */
    if (object->private.pPassword && object->ulPasswordLen) {
        sv_setpvn(sv, object->private.pPassword, object->ulPasswordLen);
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
            free(object->private.pPassword);
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
        free(object->private.pPassword);
    }

    /* uncoverable branch 1 */
    if (!(object->private.pPassword = calloc(1, l))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }
    object->private.ulPasswordLen = &(object->ulPasswordLen);
    object->ulPasswordLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAM* crypt_pkcs11_ck_otp_param_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAM* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM));
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
        free(object->private.pValue);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pValue) {
        CK_BYTE_PTR pValue = calloc(object->private.ulValueLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pValue) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pValue, object->private.pValue, object->private.ulValueLen);
        object->private.pValue = pValue;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_otp_param_DESTROY(Crypt__PKCS11__CK_OTP_PARAM* object) {
    if (object) {
        if (object->private.pValue) {
            free(object->private.pValue);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pValue, object->private.ulValueLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_set_pValue(Crypt__PKCS11__CK_OTP_PARAM* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pValue);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pValue) {
        free(object->private.pValue);
    }
    object->private.pValue = n;
    object->private.ulValueLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAMS* crypt_pkcs11_ck_otp_params_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAMS));
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
                free(object->private.pParams[ulCount].pValue);
            }
        }
        free(object->private.pParams);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pParams) {
        CK_OTP_PARAM_PTR params;
        CK_ULONG ulCount;

        /* uncoverable branch 1 */
        if (!(params = calloc(object->private.ulCount, sizeof(CK_OTP_PARAM)))) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }

        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            params[ulCount].type = object->private.pParams[ulCount].type;
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                /* uncoverable branch 1 */
                if (!(params[ulCount].pValue = calloc(1, object->private.pParams[ulCount].ulValueLen))) {
                    /* uncoverable block 0 */
                    __croak("memory allocation error");
                }
                memcpy(params[ulCount].pValue, object->private.pParams[ulCount].pValue, object->private.pParams[ulCount].ulValueLen);
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
                    free(object->private.pParams[ulCount].pValue);
                }
            }
            free(object->private.pParams);
        }
        free(object);
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
        /* uncoverable branch 1 */
        if (!(param = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM)))) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.pParams[ulCount].type;
        /* uncoverable branch 1 */
        if (object->private.pParams[ulCount].pValue) {
            /* uncoverable branch 1 */
            if (!(param->private.pValue = calloc(1, object->private.pParams[ulCount].ulValueLen))) {
                /* uncoverable begin */
                free(param);
                return CKR_HOST_MEMORY;
                /* uncoverable end */
            }
            memcpy(param->private.pValue, object->private.pParams[ulCount].pValue, object->private.pParams[ulCount].ulValueLen);
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
    CK_OTP_PARAM_PTR params;
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

    /* uncoverable branch 1 */
    if (!(params = calloc(paramCount, sizeof(CK_OTP_PARAM)))) {
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
            /* uncoverable branch 1 */
            if (!(params[key].pValue = calloc(1, param->private.ulValueLen))) {
                /* uncoverable begin */
                rv = CKR_HOST_MEMORY;
                break;
                /* uncoverable end */
            }

            memcpy(params[key].pValue, param->private.pValue, param->private.ulValueLen);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    /* uncoverable begin */
    if (rv != CKR_OK) {
        for (ulCount = 0; ulCount < paramCount; ulCount++) {
            if (params[ulCount].pValue) {
                free(params[ulCount].pValue);
            }
        }
        free(params);
        return rv;
    }
    /* uncoverable end */

    if (object->private.pParams) {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                free(object->private.pParams[ulCount].pValue);
            }
        }
        free(object->private.pParams);
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
    Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO));
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
                free(object->private.pParams[ulCount].pValue);
            }
        }
        free(object->private.pParams);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pParams) {
        CK_OTP_PARAM_PTR params;
        CK_ULONG ulCount;

        /* uncoverable branch 1 */
        if (!(params = calloc(object->private.ulCount, sizeof(CK_OTP_PARAM)))) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }

        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            params[ulCount].type = object->private.pParams[ulCount].type;
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                /* uncoverable branch 1 */
                if (!(params[ulCount].pValue = calloc(1, object->private.pParams[ulCount].ulValueLen))) {
                    /* uncoverable block 0 */
                    __croak("memory allocation error");
                }
                memcpy(params[ulCount].pValue, object->private.pParams[ulCount].pValue, object->private.pParams[ulCount].ulValueLen);
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
                    free(object->private.pParams[ulCount].pValue);
                }
            }
            free(object->private.pParams);
        }
        free(object);
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
        /* uncoverable branch 1 */
        if (!(param = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM)))) {
            /* uncoverable block 0 */
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.pParams[ulCount].type;
        /* uncoverable branch 1 */
        if (object->private.pParams[ulCount].pValue) {
            /* uncoverable branch 1 */
            if (!(param->private.pValue = calloc(1, object->private.pParams[ulCount].ulValueLen))) {
                /* uncoverable begin */
                free(param);
                return CKR_HOST_MEMORY;
                /* uncoverable end */
            }
            memcpy(param->private.pValue, object->private.pParams[ulCount].pValue, object->private.pParams[ulCount].ulValueLen);
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
    CK_OTP_PARAM_PTR params;
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

    /* uncoverable branch 1 */
    if (!(params = calloc(paramCount, sizeof(CK_OTP_PARAM)))) {
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
            /* uncoverable branch 1 */
            if (!(params[key].pValue = calloc(1, param->private.ulValueLen))) {
                /* uncoverable begin */
                rv = CKR_HOST_MEMORY;
                break;
                /* uncoverable end */
            }

            memcpy(params[key].pValue, param->private.pValue, param->private.ulValueLen);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    /* uncoverable begin */
    if (rv != CKR_OK) {
        for (ulCount = 0; ulCount < paramCount; ulCount++) {
            if (params[ulCount].pValue) {
                free(params[ulCount].pValue);
            }
        }
        free(params);
        return rv;
    }
    /* uncoverable end */

    if (object->private.pParams) {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
            /* uncoverable branch 1 */
            if (object->private.pParams[ulCount].pValue) {
                free(object->private.pParams[ulCount].pValue);
            }
        }
        free(object->private.pParams);
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
    Crypt__PKCS11__CK_KIP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_KIP_PARAMS));
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
        free(object->pMechanism.pParameter);
    }
    memset(&(object->pMechanism), 0, sizeof(CK_MECHANISM));
    if (object->private.pSeed) {
        free(object->private.pSeed);
    }
    memcpy(&(object->private), p, l);

    /* uncoverable branch 1 */
    if (object->private.pMechanism) {
        memcpy(&(object->pMechanism), object->private.pMechanism, sizeof(CK_MECHANISM));
        if (object->pMechanism.pParameter) {
            CK_VOID_PTR pParameter = calloc(object->pMechanism.ulParameterLen, 1);
            /* uncoverable branch 0 */
            if (!pParameter) {
                /* uncoverable block 0 */
                __croak("memory allocation error");
            }
            memcpy(pParameter, object->pMechanism.pParameter, object->pMechanism.ulParameterLen);
            object->pMechanism.pParameter = pParameter;
        }
    }
    object->private.pMechanism = &(object->pMechanism);

    if (object->private.pSeed) {
        CK_BYTE_PTR pSeed = calloc(object->private.ulSeedLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pSeed) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pSeed, object->private.pSeed, object->private.ulSeedLen);
        object->private.pSeed = pSeed;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_kip_params_DESTROY(Crypt__PKCS11__CK_KIP_PARAMS* object) {
    if (object) {
        if (object->pMechanism.pParameter) {
            free(object->pMechanism.pParameter);
        }
        if (object->private.pSeed) {
            free(object->private.pSeed);
        }
        free(object);
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

    if (object->pMechanism.ulParameterLen
        /* uncoverable branch 1 */
        && !(pParameter = calloc(1, object->pMechanism.ulParameterLen)))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    if (pParameter) {
        memcpy(pParameter, object->pMechanism.pParameter, object->pMechanism.ulParameterLen);
    }

    if (sv->private.pParameter) {
        free(sv->private.pParameter);
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

    if (sv->private.ulParameterLen
        /* uncoverable branch 1 */
        && !(pParameter = calloc(1, sv->private.ulParameterLen)))
    {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    if (pParameter) {
        memcpy(pParameter, sv->private.pParameter, sv->private.ulParameterLen);
    }

    if (object->pMechanism.pParameter) {
        free(object->pMechanism.pParameter);
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
    sv_setpvn(sv, object->private.pSeed, object->private.ulSeedLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_pSeed(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pSeed);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pSeed) {
        free(object->private.pSeed);
    }
    object->private.pSeed = n;
    object->private.ulSeedLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CTR_PARAMS* crypt_pkcs11_ck_aes_ctr_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CTR_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_CTR_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_aes_ctr_params_DESTROY(Crypt__PKCS11__CK_AES_CTR_PARAMS* object) {
    if (object) {
        free(object);
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
        memset(object->private.cb, 0, 16 * sizeof(CK_BYTE));
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

    memcpy(object->private.cb, p, 16 * sizeof(CK_BYTE));

    return CKR_OK;
}

Crypt__PKCS11__CK_AES_GCM_PARAMS* crypt_pkcs11_ck_aes_gcm_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_GCM_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_GCM_PARAMS));
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
        free(object->private.pIv);
    }
    if (object->private.pAAD) {
        free(object->private.pAAD);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pIv) {
        CK_BYTE_PTR pIv = calloc(object->private.ulIvLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pIv) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pIv, object->private.pIv, object->private.ulIvLen);
        object->private.pIv = pIv;
    }
    if (object->private.pAAD) {
        CK_BYTE_PTR pAAD = calloc(object->private.ulAADLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pAAD) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pAAD, object->private.pAAD, object->private.ulAADLen);
        object->private.pAAD = pAAD;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aes_gcm_params_DESTROY(Crypt__PKCS11__CK_AES_GCM_PARAMS* object) {
    if (object) {
        if (object->private.pIv) {
            free(object->private.pIv);
        }
        if (object->private.pAAD) {
            free(object->private.pAAD);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pIv, object->private.ulIvLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_pIv(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pIv);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pIv) {
        free(object->private.pIv);
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
    sv_setpvn(sv, object->private.pAAD, object->private.ulAADLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_pAAD(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pAAD);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pAAD) {
        free(object->private.pAAD);
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
    Crypt__PKCS11__CK_AES_CCM_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_CCM_PARAMS));
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
        free(object->private.pNonce);
    }
    if (object->private.pAAD) {
        free(object->private.pAAD);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pNonce) {
        CK_BYTE_PTR pNonce = calloc(object->private.ulNonceLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pNonce) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pNonce, object->private.pNonce, object->private.ulNonceLen);
        object->private.pNonce = pNonce;
    }
    if (object->private.pAAD) {
        CK_BYTE_PTR pAAD = calloc(object->private.ulAADLen, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pAAD) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pAAD, object->private.pAAD, object->private.ulAADLen);
        object->private.pAAD = pAAD;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aes_ccm_params_DESTROY(Crypt__PKCS11__CK_AES_CCM_PARAMS* object) {
    if (object) {
        if (object->private.pNonce) {
            free(object->private.pNonce);
        }
        if (object->private.pAAD) {
            free(object->private.pAAD);
        }
        free(object);
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
    sv_setpvn(sv, object->private.pNonce, object->private.ulNonceLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_set_pNonce(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pNonce);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pNonce) {
        free(object->private.pNonce);
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
    sv_setpvn(sv, object->private.pAAD, object->private.ulAADLen);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_set_pAAD(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pAAD);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pAAD) {
        free(object->private.pAAD);
    }
    object->private.pAAD = n;
    object->private.ulAADLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* crypt_pkcs11_ck_camellia_ctr_params_new(const char* class) {
    Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS));
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

    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_camellia_ctr_params_DESTROY(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object) {
    if (object) {
        free(object);
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
        memset(object->private.cb, 0, 16 * sizeof(CK_BYTE));
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

    memcpy(object->private.cb, p, 16 * sizeof(CK_BYTE));

    return CKR_OK;
}

Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS));
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
        free(object->private.pData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pData) {
        CK_BYTE_PTR pData = calloc(object->private.length, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pData, object->private.pData, object->private.length);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            free(object->private.pData);
        }
        free(object);
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
        memset(object->private.iv, 0, 16 * sizeof(CK_BYTE));
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

    memcpy(object->private.iv, p, 16 * sizeof(CK_BYTE));

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
    sv_setpvn(sv, object->private.pData, object->private.length);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pData) {
        free(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_aria_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS));
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
        free(object->private.pData);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pData) {
        CK_BYTE_PTR pData = calloc(object->private.length, sizeof(CK_BYTE));
        /* uncoverable branch 0 */
        if (!pData) {
            /* uncoverable block 0 */
            __croak("memory allocation error");
        }
        memcpy(pData, object->private.pData, object->private.length);
        object->private.pData = pData;
    }
    return CKR_OK;
}

void crypt_pkcs11_ck_aria_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    if (object) {
        if (object->private.pData) {
            free(object->private.pData);
        }
        free(object);
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
        memset(object->private.iv, 0, 16 * sizeof(CK_BYTE));
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

    memcpy(object->private.iv, p, 16 * sizeof(CK_BYTE));

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
    sv_setpvn(sv, object->private.pData, object->private.length);
    SvSETMAGIC(sv);

    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* sv) {
    CK_BYTE_PTR n;
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
            free(object->private.pData);
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

    /* uncoverable branch 1 */
    if (!(n = calloc(1, l + 1))) {
        /* uncoverable block 0 */
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pData) {
        free(object->private.pData);
    }
    object->private.pData = n;
    object->private.length = l;

    return CKR_OK;
}

