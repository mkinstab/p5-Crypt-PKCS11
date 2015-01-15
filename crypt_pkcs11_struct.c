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

extern int crypt_pkcs11_xs_SvUOK(SV* sv);

Crypt__PKCS11__CK_VERSION* crypt_pkcs11_ck_version_new(const char* class) {
    Crypt__PKCS11__CK_VERSION* object = calloc(1, sizeof(Crypt__PKCS11__CK_VERSION));
    if (!object) {
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_version_toBytes(Crypt__PKCS11__CK_VERSION* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_VERSION));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_mechanism_toBytes(Crypt__PKCS11__CK_MECHANISM* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_MECHANISM));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rsa_pkcs_oaep_params_toBytes(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RSA_PKCS_OAEP_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rsa_pkcs_pss_params_toBytes(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RSA_PKCS_PSS_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ecdh1_derive_params_toBytes(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_ECDH1_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ecdh2_derive_params_toBytes(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_ECDH2_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ecmqv_derive_params_toBytes(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_ECMQV_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_x9_42_dh1_derive_params_toBytes(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_X9_42_DH1_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_x9_42_dh2_derive_params_toBytes(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_X9_42_DH2_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_x9_42_mqv_derive_params_toBytes(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_X9_42_MQV_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_kea_derive_params_toBytes(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_KEA_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc2_cbc_params_toBytes(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RC2_CBC_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.iv, 0, 8 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc2_mac_general_params_toBytes(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RC2_MAC_GENERAL_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc5_params_toBytes(Crypt__PKCS11__CK_RC5_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RC5_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc5_cbc_params_toBytes(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RC5_CBC_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_rc5_mac_general_params_toBytes(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_RC5_MAC_GENERAL_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_des_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.iv, 0, 8 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.iv, 0, 16 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_skipjack_private_wrap_params_toBytes(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_skipjack_relayx_params_toBytes(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_SKIPJACK_RELAYX_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    else {
        if (!(object->private.pInitVector = calloc(1, 8))) {
            free(object);
            croak("memory allocation error");
            return 0;
        }
    }
    return object;
}

SV* crypt_pkcs11_ck_pbe_params_toBytes(Crypt__PKCS11__CK_PBE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_PBE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    return CKR_OK;
}

void crypt_pkcs11_ck_pbe_params_DESTROY(Crypt__PKCS11__CK_PBE_PARAMS* object) {
    if (object) {
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
    sv_setpvn(sv, object->private.pInitVector, 8);
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

    if (!SvOK(sv)) {
        memset(object->private.pInitVector, 0, 8);
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
        return CKR_GENERAL_ERROR;
    }
    if (l != 8) {
        return CKR_ARGUMENTS_BAD;
    }

    memcpy(object->private.pInitVector, p, 8);

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
    sv_utf8_upgrade(sv);
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
        return CKR_GENERAL_ERROR;
    }

    if (!sv_utf8_downgrade(_sv, 0)
        || !(p = SvPV(_sv, l)))
    {
        SvREFCNT_dec(_sv);
        return CKR_GENERAL_ERROR;
    }

    if (!(n = calloc(1, l + 1))) {
        SvREFCNT_dec(_sv);
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pPassword) {
        free(object->private.pPassword);
    }
    object->private.pPassword = n;
    object->private.ulPasswordLen = l;

    SvREFCNT_dec(_sv);
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_key_wrap_set_oaep_params_toBytes(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_random_data_toBytes(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_RANDOM_DATA));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    else {
        object->private.pVersion = &(object->pVersion);
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_master_key_derive_params_toBytes(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
    memcpy(&(object->private), p, l);

    if (object->private.pVersion) {
        memcpy(&(object->pVersion), object->private.pVersion, sizeof(CK_VERSION));
        free(object->private.pVersion);
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
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        croak("memory allocation error");
    }
    else {
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_key_mat_out_toBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_KEY_MAT_OUT));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_fromBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* sv) {
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
        || l != sizeof(CK_SSL3_KEY_MAT_OUT))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pIVClient) {
        free(object->private.pIVClient);
    }
    if (object->private.pIVServer) {
        free(object->private.pIVServer);
    }
    memcpy(&(object->private), p, l);

    return CKR_OK;
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
        croak("memory allocation error");
    }
    else {
        object->private.pReturnedKeyMaterial = &(object->pReturnedKeyMaterial);
    }
    return object;
}

SV* crypt_pkcs11_ck_ssl3_key_mat_params_toBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_SSL3_KEY_MAT_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_fromBytes(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* sv) {
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
        || l != sizeof(CK_SSL3_KEY_MAT_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
    }
    memcpy(&(object->private), p, l);

    return CKR_OK;
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
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        && !(pIVClient = calloc(object->private.ulIVSizeInBits / 8, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (object->private.ulIVSizeInBits
        && !(pIVServer = calloc(object->private.ulIVSizeInBits / 8, sizeof(CK_BYTE))))
    {
        free(pIVClient);
        return CKR_HOST_MEMORY;
    }

    if (pIVClient) {
        memcpy(pIVClient, object->pReturnedKeyMaterial.pIVClient, (object->private.ulIVSizeInBits / 8) * sizeof(CK_BYTE));
    }
    if (pIVServer) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_tls_prf_params_toBytes(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_TLS_PRF_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
    if (!SvOK(sv)) {
        if (!object->pulOutputLen) {
            return CKR_FUNCTION_FAILED;
        }

        if (object->private.pOutput) {
            free(object->private.pOutput);
        }

        if (!(object->private.pOutput = calloc(1, object->pulOutputLen))) {
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

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

    if (!(object->private.pOutput = calloc(1, l))) {
        return CKR_HOST_MEMORY;
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    object->pulOutputLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_RANDOM_DATA* crypt_pkcs11_ck_wtls_random_data_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_RANDOM_DATA));
    if (!object) {
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_random_data_toBytes(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_RANDOM_DATA));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    else {
        if (!(object->private.pVersion = calloc(1, 1))) {
            free(object);
            croak("memory allocation error");
            return 0;
        }
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_master_key_derive_params_toBytes(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_MASTER_KEY_DERIVE_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
    if (object->private.pVersion) {
        free(object->private.pVersion);
    }
    memcpy(&(object->private), p, l);

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
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_prf_params_toBytes(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_PRF_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
    if (!SvOK(sv)) {
        if (!object->pulOutputLen) {
            return CKR_FUNCTION_FAILED;
        }

        if (object->private.pOutput) {
            free(object->private.pOutput);
        }

        if (!(object->private.pOutput = calloc(1, object->pulOutputLen))) {
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

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

    if (!(object->private.pOutput = calloc(1, l))) {
        return CKR_HOST_MEMORY;
    }
    object->private.pulOutputLen = &(object->pulOutputLen);
    object->pulOutputLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* crypt_pkcs11_ck_wtls_key_mat_out_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT));
    if (!object) {
        croak("memory allocation error");
    }
    else {
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_key_mat_out_toBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_KEY_MAT_OUT));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_fromBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* sv) {
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
        || l != sizeof(CK_WTLS_KEY_MAT_OUT))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.pIV) {
        free(object->private.pIV);
    }
    memcpy(&(object->private), p, l);

    return CKR_OK;
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
        croak("memory allocation error");
    }
    else {
        object->private.pReturnedKeyMaterial = &(object->pReturnedKeyMaterial);
    }
    return object;
}

SV* crypt_pkcs11_ck_wtls_key_mat_params_toBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_WTLS_KEY_MAT_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_fromBytes(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* sv) {
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
        || l != sizeof(CK_WTLS_KEY_MAT_PARAMS))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (object->private.RandomInfo.pClientRandom) {
        free(object->private.RandomInfo.pClientRandom);
    }
    if (object->private.RandomInfo.pServerRandom) {
        free(object->private.RandomInfo.pServerRandom);
    }
    memcpy(&(object->private), p, l);

    return CKR_OK;
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
        && !(pClientRandom = calloc(object->private.RandomInfo.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (object->private.RandomInfo.pServerRandom
        && !(pServerRandom = calloc(object->private.RandomInfo.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        && !(pClientRandom = calloc(sv->private.ulClientRandomLen, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }
    if (sv->private.pServerRandom
        && !(pServerRandom = calloc(sv->private.ulServerRandomLen, sizeof(CK_BYTE))))
    {
        free(pClientRandom);
        return CKR_HOST_MEMORY;
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
        && !(pIV = calloc(object->private.ulIVSizeInBits / 8, sizeof(CK_BYTE))))
    {
        return CKR_HOST_MEMORY;
    }

    if (pIV) {
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
        croak("memory allocation error");
    }
    else {
        object->private.pSigningMechanism = &(object->pSigningMechanism);
        object->private.pDigestMechanism = &(object->pDigestMechanism);
    }
    return object;
}

SV* crypt_pkcs11_ck_cms_sig_params_toBytes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_CMS_SIG_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
    memcpy(&(object->private), p, l);

    if (object->private.pSigningMechanism) {
        memcpy(&(object->pSigningMechanism), object->private.pSigningMechanism, sizeof(CK_MECHANISM));
        free(object->private.pSigningMechanism);
    }
    object->private.pSigningMechanism = &(object->pSigningMechanism);

    if (object->private.pDigestMechanism) {
        memcpy(&(object->pDigestMechanism), object->private.pDigestMechanism, sizeof(CK_MECHANISM));
        free(object->private.pDigestMechanism);
    }
    object->private.pDigestMechanism = &(object->pDigestMechanism);

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
        && !(pParameter = calloc(1, object->pSigningMechanism.ulParameterLen)))
    {
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
        && !(pParameter = calloc(1, sv->private.ulParameterLen)))
    {
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
        && !(pParameter = calloc(1, object->pDigestMechanism.ulParameterLen)))
    {
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
        && !(pParameter = calloc(1, sv->private.ulParameterLen)))
    {
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
    sv_utf8_upgrade(sv);
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
        return CKR_GENERAL_ERROR;
    }

    if (!sv_utf8_downgrade(_sv, 0)
        || !(p = SvPV(_sv, l)))
    {
        SvREFCNT_dec(_sv);
        return CKR_GENERAL_ERROR;
    }

    if (!(n = calloc(1, l + 1))) {
        SvREFCNT_dec(_sv);
        return CKR_HOST_MEMORY;
    }

    memcpy(n, p, l);
    if (object->private.pContentType) {
        free(object->private.pContentType);
    }
    object->private.pContentType = n;

    SvREFCNT_dec(_sv);
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_key_derivation_string_data_toBytes(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_KEY_DERIVATION_STRING_DATA));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_pkcs5_pbkd2_params_toBytes(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_PKCS5_PBKD2_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
    if (!SvOK(sv)) {
        if (!object->ulPasswordLen) {
            return CKR_FUNCTION_FAILED;
        }

        if (object->private.pPassword) {
            free(object->private.pPassword);
        }

        if (!(object->private.pPassword = calloc(1, object->ulPasswordLen))) {
            return CKR_HOST_MEMORY;
        }
        return CKR_OK;
    }

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

    if (!(object->private.pPassword = calloc(1, l))) {
        return CKR_HOST_MEMORY;
    }
    object->private.ulPasswordLen = &(object->ulPasswordLen);
    object->ulPasswordLen = l;

    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAM* crypt_pkcs11_ck_otp_param_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAM* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM));
    if (!object) {
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_otp_param_toBytes(Crypt__PKCS11__CK_OTP_PARAM* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_OTP_PARAM));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_otp_params_toBytes(Crypt__PKCS11__CK_OTP_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_OTP_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
            if (object->private.pParams[ulCount].pValue) {
                free(object->private.pParams[ulCount].pValue);
            }
        }
        free(object->private.pParams);
    }
    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_otp_params_DESTROY(Crypt__PKCS11__CK_OTP_PARAMS* object) {
    if (object) {
        if (object->private.pParams) {
            CK_ULONG ulCount;
            for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
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
        if (!(param = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM)))) {
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.pParams[ulCount].type;
        if (object->private.pParams[ulCount].pValue) {
            if (!(param->private.pValue = calloc(1, object->private.pParams[ulCount].ulValueLen))) {
                free(param);
                return CKR_HOST_MEMORY;
            }
            memcpy(param->private.pValue, object->private.pParams[ulCount].pValue, object->private.pParams[ulCount].ulValueLen);
            param->private.ulValueLen = object->private.pParams[ulCount].ulValueLen;
        }

        paramSV = sv_newmortal();
        sv_setref_pv(paramSV, "Crypt::PKCS11::CK_OTP_PARAMPtr", param);
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

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        if (!(item = av_fetch(sv, key, 0))
            || !*item
            || !SvROK(*item)
            || !(entry = SvRV(*item))
            || !sv_isobject(entry)
            || !sv_derived_from(entry, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            return CKR_ARGUMENTS_BAD;
        }
        paramCount++;
    }

    if (!(params = calloc(paramCount, sizeof(CK_OTP_PARAM)))) {
        return CKR_HOST_MEMORY;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        if (!(item = av_fetch(sv, key, 0))
            || !*item
            || !SvROK(*item)
            || !(entry = SvRV(*item))
            || !sv_isobject(entry)
            || !sv_derived_from(entry, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            for (ulCount = 0; ulCount < paramCount; ulCount++) {
                if (params[ulCount].pValue) {
                    free(params[ulCount].pValue);
                }
            }
            free(params);
            return CKR_ARGUMENTS_BAD;
        }

        tmp = SvIV((SV*)SvRV(entry));
        if (!(param = INT2PTR(Crypt__PKCS11__CK_OTP_PARAM*, tmp))) {
            for (ulCount = 0; ulCount < paramCount; ulCount++) {
                if (params[ulCount].pValue) {
                    free(params[ulCount].pValue);
                }
            }
            free(params);
            return CKR_GENERAL_ERROR;
        }

        if (param->private.pValue) {
            if (!(params[key].pValue = calloc(1, param->private.ulValueLen))) {
                for (ulCount = 0; ulCount < paramCount; ulCount++) {
                    if (params[ulCount].pValue) {
                        free(params[ulCount].pValue);
                    }
                }
                free(params);
                return CKR_HOST_MEMORY;
            }

            memcpy(params[key].pValue, param->private.pValue, param->private.ulValueLen);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    if (object->private.pParams) {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_otp_signature_info_toBytes(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_OTP_SIGNATURE_INFO));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
            if (object->private.pParams[ulCount].pValue) {
                free(object->private.pParams[ulCount].pValue);
            }
        }
        free(object->private.pParams);
    }
    memcpy(&(object->private), p, l);

    return CKR_OK;
}

void crypt_pkcs11_ck_otp_signature_info_DESTROY(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object) {
    if (object) {
        if (object->private.pParams) {
            CK_ULONG ulCount;
            for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
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
        if (!(param = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM)))) {
            return CKR_HOST_MEMORY;
        }

        param->private.type = object->private.pParams[ulCount].type;
        if (object->private.pParams[ulCount].pValue) {
            if (!(param->private.pValue = calloc(1, object->private.pParams[ulCount].ulValueLen))) {
                free(param);
                return CKR_HOST_MEMORY;
            }
            memcpy(param->private.pValue, object->private.pParams[ulCount].pValue, object->private.pParams[ulCount].ulValueLen);
            param->private.ulValueLen = object->private.pParams[ulCount].ulValueLen;
        }

        paramSV = sv_newmortal();
        sv_setref_pv(paramSV, "Crypt::PKCS11::CK_OTP_PARAMPtr", param);
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

    if (!object) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!sv) {
        return CKR_ARGUMENTS_BAD;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        if (!(item = av_fetch(sv, key, 0))
            || !*item
            || !SvROK(*item)
            || !(entry = SvRV(*item))
            || !sv_isobject(entry)
            || !sv_derived_from(entry, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            return CKR_ARGUMENTS_BAD;
        }
        paramCount++;
    }

    if (!(params = calloc(paramCount, sizeof(CK_OTP_PARAM)))) {
        return CKR_HOST_MEMORY;
    }

    for (key = 0; key < av_len(sv) + 1; key++) {
        if (!(item = av_fetch(sv, key, 0))
            || !*item
            || !SvROK(*item)
            || !(entry = SvRV(*item))
            || !sv_isobject(entry)
            || !sv_derived_from(entry, "Crypt::PKCS11::CK_OTP_PARAMPtr"))
        {
            for (ulCount = 0; ulCount < paramCount; ulCount++) {
                if (params[ulCount].pValue) {
                    free(params[ulCount].pValue);
                }
            }
            free(params);
            return CKR_ARGUMENTS_BAD;
        }

        tmp = SvIV((SV*)SvRV(entry));
        if (!(param = INT2PTR(Crypt__PKCS11__CK_OTP_PARAM*, tmp))) {
            for (ulCount = 0; ulCount < paramCount; ulCount++) {
                if (params[ulCount].pValue) {
                    free(params[ulCount].pValue);
                }
            }
            free(params);
            return CKR_GENERAL_ERROR;
        }

        if (param->private.pValue) {
            if (!(params[key].pValue = calloc(1, param->private.ulValueLen))) {
                for (ulCount = 0; ulCount < paramCount; ulCount++) {
                    if (params[ulCount].pValue) {
                        free(params[ulCount].pValue);
                    }
                }
                free(params);
                return CKR_HOST_MEMORY;
            }

            memcpy(params[key].pValue, param->private.pValue, param->private.ulValueLen);
            params[key].ulValueLen = param->private.ulValueLen;
        }
    }

    if (object->private.pParams) {
        for (ulCount = 0; ulCount < object->private.ulCount; ulCount++) {
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
        croak("memory allocation error");
    }
    else {
        object->private.pMechanism = &(object->pMechanism);
    }
    return object;
}

SV* crypt_pkcs11_ck_kip_params_toBytes(Crypt__PKCS11__CK_KIP_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_KIP_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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
    if (object->private.pSeed) {
        free(object->private.pSeed);
    }
    memcpy(&(object->private), p, l);

    if (object->private.pMechanism) {
        memcpy(&(object->pMechanism), object->private.pMechanism, sizeof(CK_MECHANISM));
        free(object->private.pMechanism);
    }
    object->private.pMechanism = &(object->pMechanism);

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
        && !(pParameter = calloc(1, object->pMechanism.ulParameterLen)))
    {
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
        && !(pParameter = calloc(1, sv->private.ulParameterLen)))
    {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_ctr_params_toBytes(Crypt__PKCS11__CK_AES_CTR_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_AES_CTR_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.cb, 0, 16 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_gcm_params_toBytes(Crypt__PKCS11__CK_AES_GCM_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_AES_GCM_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aes_ccm_params_toBytes(Crypt__PKCS11__CK_AES_CCM_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_AES_CCM_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!(n = calloc(1, l + 1))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_camellia_ctr_params_toBytes(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_CAMELLIA_CTR_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.cb, 0, 16 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.iv, 0, 16 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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

    if (!(n = calloc(1, l + 1))) {
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
        croak("memory allocation error");
    }
    return object;
}

SV* crypt_pkcs11_ck_aria_cbc_encrypt_data_params_toBytes(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    SV* retval = NULL_PTR;

    if (object) {
        retval = newSVpvn((const char*)&(object->private), sizeof(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS));
    }
    else {
        retval = newSVsv(&PL_sv_undef);
    }

    return retval;
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

    if (!SvOK(sv)) {
        memset(object->private.iv, 0, 16 * sizeof(CK_BYTE));
        return CKR_OK;
    }

    if (!SvPOK(sv)) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!(p = SvPVbyte(sv, l))) {
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

    if (!(n = calloc(1, l + 1))) {
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

