/*
 * Copyright (c) 2014 Jerry Lundström <lundstrom.jerry@gmail.com>
 * Copyright (c) 2014 .SE (The Internet Infrastructure Foundation)
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

Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* crypt_pkcs11_ck_rsa_pkcs_oaep_params_new(const char* class) {
    Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rsa_pkcs_oaep_params_DESTROY(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* hashAlg) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* hashAlg) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_mgf(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* mgf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_mgf(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* mgf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_source(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* source) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_source(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* source) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_pSourceData(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* pSourceData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_pSourceData(Crypt__PKCS11__CK_RSA_PKCS_OAEP_PARAMS* object, SV* pSourceData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* crypt_pkcs11_ck_rsa_pkcs_pss_params_new(const char* class) {
    Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rsa_pkcs_pss_params_DESTROY(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_get_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* hashAlg) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_set_hashAlg(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* hashAlg) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_get_mgf(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* mgf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_set_mgf(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* mgf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_get_sLen(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sLen) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rsa_pkcs_pss_params_set_sLen(Crypt__PKCS11__CK_RSA_PKCS_PSS_PARAMS* object, SV* sLen) {
    return CKR_OK;
}

Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* crypt_pkcs11_ck_ecdh1_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_ecdh1_derive_params_DESTROY(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_get_kdf(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_kdf(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_get_pSharedData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* pSharedData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* pSharedData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_get_pPublicData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh1_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECDH1_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* crypt_pkcs11_ck_ecdh2_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_ecdh2_derive_params_DESTROY(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_kdf(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_kdf(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_pSharedData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* pSharedData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* pSharedData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_hPrivateData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_hPrivateData(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_ulPublicDataLen2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_ulPublicDataLen2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData2(Crypt__PKCS11__CK_ECDH2_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* crypt_pkcs11_ck_ecmqv_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_ecmqv_derive_params_DESTROY(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_kdf(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_kdf(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_pSharedData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* pSharedData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pSharedData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* pSharedData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_hPrivateData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_hPrivateData(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_ulPublicDataLen2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_ulPublicDataLen2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData2(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_get_publicKey(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* publicKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ecmqv_derive_params_set_publicKey(Crypt__PKCS11__CK_ECMQV_DERIVE_PARAMS* object, SV* publicKey) {
    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_dh1_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_x9_42_dh1_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_get_kdf(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_kdf(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* pOtherInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* pOtherInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pPublicData(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_DH1_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_dh2_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_x9_42_dh2_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_kdf(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_kdf(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* pOtherInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* pOtherInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_hPrivateData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_hPrivateData(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_ulPublicDataLen2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_ulPublicDataLen2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData2(Crypt__PKCS11__CK_X9_42_DH2_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* crypt_pkcs11_ck_x9_42_mqv_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_x9_42_mqv_derive_params_DESTROY(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_kdf(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_kdf(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* kdf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pOtherInfo(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* pOtherInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pOtherInfo(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* pOtherInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_hPrivateData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_hPrivateData(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* hPrivateData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_ulPublicDataLen2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_ulPublicDataLen2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* ulPublicDataLen2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData2(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* pPublicData2) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_get_publicKey(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* publicKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_x9_42_mqv_derive_params_set_publicKey(Crypt__PKCS11__CK_X9_42_MQV_DERIVE_PARAMS* object, SV* publicKey) {
    return CKR_OK;
}

Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* crypt_pkcs11_ck_kea_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_kea_derive_params_DESTROY(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_isSender(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* isSender) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_isSender(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* isSender) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_pRandomA(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* pRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pRandomA(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* pRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_pRandomB(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* pRandomB) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pRandomB(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* pRandomB) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_get_pPublicData(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kea_derive_params_set_pPublicData(Crypt__PKCS11__CK_KEA_DERIVE_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_RC2_CBC_PARAMS* crypt_pkcs11_ck_rc2_cbc_params_new(const char* class) {
    Crypt__PKCS11__CK_RC2_CBC_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC2_CBC_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rc2_cbc_params_DESTROY(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_get_ulEffectiveBits(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* ulEffectiveBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_set_ulEffectiveBits(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* ulEffectiveBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_get_iv(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_cbc_params_set_iv(Crypt__PKCS11__CK_RC2_CBC_PARAMS* object, SV* iv) {
    return CKR_OK;
}

Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* crypt_pkcs11_ck_rc2_mac_general_params_new(const char* class) {
    Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rc2_mac_general_params_DESTROY(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_get_ulEffectiveBits(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* ulEffectiveBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_set_ulEffectiveBits(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* ulEffectiveBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_get_ulMacLength(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* ulMacLength) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc2_mac_general_params_set_ulMacLength(Crypt__PKCS11__CK_RC2_MAC_GENERAL_PARAMS* object, SV* ulMacLength) {
    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_PARAMS* crypt_pkcs11_ck_rc5_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC5_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rc5_params_DESTROY(Crypt__PKCS11__CK_RC5_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rc5_params_get_ulWordsize(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* ulWordsize) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_params_set_ulWordsize(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* ulWordsize) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_params_get_ulRounds(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* ulRounds) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_params_set_ulRounds(Crypt__PKCS11__CK_RC5_PARAMS* object, SV* ulRounds) {
    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_CBC_PARAMS* crypt_pkcs11_ck_rc5_cbc_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_CBC_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC5_CBC_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rc5_cbc_params_DESTROY(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_get_ulWordsize(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* ulWordsize) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_ulWordsize(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* ulWordsize) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_get_ulRounds(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* ulRounds) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_ulRounds(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* ulRounds) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_get_pIv(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* pIv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_cbc_params_set_pIv(Crypt__PKCS11__CK_RC5_CBC_PARAMS* object, SV* pIv) {
    return CKR_OK;
}

Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* crypt_pkcs11_ck_rc5_mac_general_params_new(const char* class) {
    Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS));
    return object;
}

void crypt_pkcs11_ck_rc5_mac_general_params_DESTROY(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_get_ulWordsize(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* ulWordsize) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_set_ulWordsize(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* ulWordsize) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_get_ulRounds(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* ulRounds) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_set_ulRounds(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* ulRounds) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_get_ulMacLength(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* ulMacLength) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_rc5_mac_general_params_set_ulMacLength(Crypt__PKCS11__CK_RC5_MAC_GENERAL_PARAMS* object, SV* ulMacLength) {
    return CKR_OK;
}

Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_des_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS));
    return object;
}

void crypt_pkcs11_ck_des_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_DES_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_aes_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS));
    return object;
}

void crypt_pkcs11_ck_aes_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_AES_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* crypt_pkcs11_ck_skipjack_private_wrap_params_new(const char* class) {
    Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS));
    return object;
}

void crypt_pkcs11_ck_skipjack_private_wrap_params_DESTROY(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPassword(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPassword(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPublicData(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPublicData(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pRandomA(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pRandomA(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPrimeP(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pPrimeP) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPrimeP(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pPrimeP) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pBaseG(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pBaseG) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pBaseG(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pBaseG) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_get_pSubprimeQ(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pSubprimeQ) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_private_wrap_params_set_pSubprimeQ(Crypt__PKCS11__CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object, SV* pSubprimeQ) {
    return CKR_OK;
}

Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* crypt_pkcs11_ck_skipjack_relayx_params_new(const char* class) {
    Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS));
    return object;
}

void crypt_pkcs11_ck_skipjack_relayx_params_DESTROY(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldWrappedX(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldWrappedX) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldWrappedX(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldWrappedX) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pOldRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pOldRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pOldRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pNewPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPassword(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pNewPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pNewPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPublicData(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pNewPublicData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_get_pNewRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pNewRandomA) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_skipjack_relayx_params_set_pNewRandomA(Crypt__PKCS11__CK_SKIPJACK_RELAYX_PARAMS* object, SV* pNewRandomA) {
    return CKR_OK;
}

Crypt__PKCS11__CK_PBE_PARAMS* crypt_pkcs11_ck_pbe_params_new(const char* class) {
    Crypt__PKCS11__CK_PBE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_PBE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_pbe_params_DESTROY(Crypt__PKCS11__CK_PBE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_pbe_params_get_pInitVector(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* pInitVector) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pInitVector(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* pInitVector) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_get_pPassword(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* pPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pPassword(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* pPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_get_pSalt(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* pSalt) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_pSalt(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* pSalt) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_get_ulIteration(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* ulIteration) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pbe_params_set_ulIteration(Crypt__PKCS11__CK_PBE_PARAMS* object, SV* ulIteration) {
    return CKR_OK;
}

Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* crypt_pkcs11_ck_key_wrap_set_oaep_params_new(const char* class) {
    Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS));
    return object;
}

void crypt_pkcs11_ck_key_wrap_set_oaep_params_DESTROY(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_get_bBC(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* bBC) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_set_bBC(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* bBC) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_get_pX(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* pX) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_wrap_set_oaep_params_set_pX(Crypt__PKCS11__CK_KEY_WRAP_SET_OAEP_PARAMS* object, SV* pX) {
    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_RANDOM_DATA* crypt_pkcs11_ck_ssl3_random_data_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_RANDOM_DATA));
    return object;
}

void crypt_pkcs11_ck_ssl3_random_data_DESTROY(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_get_pClientRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* pClientRandom) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_set_pClientRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* pClientRandom) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_get_pServerRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* pServerRandom) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_random_data_set_pServerRandom(Crypt__PKCS11__CK_SSL3_RANDOM_DATA* object, SV* pServerRandom) {
    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* crypt_pkcs11_ck_ssl3_master_key_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_ssl3_master_key_derive_params_DESTROY(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_get_RandomInfo(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_set_RandomInfo(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_get_pVersion(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, SV* pVersion) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_master_key_derive_params_set_pVersion(Crypt__PKCS11__CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object, SV* pVersion) {
    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* crypt_pkcs11_ck_ssl3_key_mat_out_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT));
    return object;
}

void crypt_pkcs11_ck_ssl3_key_mat_out_DESTROY(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hClientMacSecret) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hClientMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hClientMacSecret) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hServerMacSecret) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hServerMacSecret(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hServerMacSecret) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hClientKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hClientKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hClientKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hServerKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_hServerKey(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* hServerKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVClient(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* pIVClient) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVClient(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* pIVClient) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVServer(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* pIVServer) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVServer(Crypt__PKCS11__CK_SSL3_KEY_MAT_OUT* object, SV* pIVServer) {
    return CKR_OK;
}

Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* crypt_pkcs11_ck_ssl3_key_mat_params_new(const char* class) {
    Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS));
    return object;
}

void crypt_pkcs11_ck_ssl3_key_mat_params_DESTROY(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_ulMacSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* ulMacSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_ulMacSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* ulMacSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_ulKeySizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* ulKeySizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_ulKeySizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* ulKeySizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_ulIVSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* ulIVSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_ulIVSizeInBits(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* ulIVSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_bIsExport(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* bIsExport) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_bIsExport(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* bIsExport) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_RandomInfo(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_RandomInfo(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_get_pReturnedKeyMaterial(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* pReturnedKeyMaterial) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_ssl3_key_mat_params_set_pReturnedKeyMaterial(Crypt__PKCS11__CK_SSL3_KEY_MAT_PARAMS* object, SV* pReturnedKeyMaterial) {
    return CKR_OK;
}

Crypt__PKCS11__CK_TLS_PRF_PARAMS* crypt_pkcs11_ck_tls_prf_params_new(const char* class) {
    Crypt__PKCS11__CK_TLS_PRF_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_TLS_PRF_PARAMS));
    return object;
}

void crypt_pkcs11_ck_tls_prf_params_DESTROY(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pSeed(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pSeed) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pSeed(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pSeed) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pLabel(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pLabel) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pLabel(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pLabel) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pOutput(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pOutput) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pOutput(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pOutput) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_get_pulOutputLen(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pulOutputLen) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_tls_prf_params_set_pulOutputLen(Crypt__PKCS11__CK_TLS_PRF_PARAMS* object, SV* pulOutputLen) {
    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_RANDOM_DATA* crypt_pkcs11_ck_wtls_random_data_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_RANDOM_DATA));
    return object;
}

void crypt_pkcs11_ck_wtls_random_data_DESTROY(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_wtls_random_data_get_pClientRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* pClientRandom) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_set_pClientRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* pClientRandom) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_get_pServerRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* pServerRandom) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_random_data_set_pServerRandom(Crypt__PKCS11__CK_WTLS_RANDOM_DATA* object, SV* pServerRandom) {
    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* crypt_pkcs11_ck_wtls_master_key_derive_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS));
    return object;
}

void crypt_pkcs11_ck_wtls_master_key_derive_params_DESTROY(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_get_DigestMechanism(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* DigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_set_DigestMechanism(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* DigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_get_RandomInfo(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_set_RandomInfo(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_get_pVersion(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* pVersion) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_master_key_derive_params_set_pVersion(Crypt__PKCS11__CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object, SV* pVersion) {
    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_PRF_PARAMS* crypt_pkcs11_ck_wtls_prf_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_PRF_PARAMS));
    return object;
}

void crypt_pkcs11_ck_wtls_prf_params_DESTROY(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_DigestMechanism(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* DigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_DigestMechanism(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* DigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pSeed(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pSeed) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pSeed(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pSeed) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pLabel(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pLabel) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pLabel(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pLabel) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pOutput(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pOutput) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pOutput(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pOutput) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_get_pulOutputLen(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pulOutputLen) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_prf_params_set_pulOutputLen(Crypt__PKCS11__CK_WTLS_PRF_PARAMS* object, SV* pulOutputLen) {
    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* crypt_pkcs11_ck_wtls_key_mat_out_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT));
    return object;
}

void crypt_pkcs11_ck_wtls_key_mat_out_DESTROY(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_get_hMacSecret(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* hMacSecret) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_hMacSecret(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* hMacSecret) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_get_hKey(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* hKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_hKey(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* hKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_get_pIV(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* pIV) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_out_set_pIV(Crypt__PKCS11__CK_WTLS_KEY_MAT_OUT* object, SV* pIV) {
    return CKR_OK;
}

Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* crypt_pkcs11_ck_wtls_key_mat_params_new(const char* class) {
    Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS));
    return object;
}

void crypt_pkcs11_ck_wtls_key_mat_params_DESTROY(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_DigestMechanism(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* DigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_DigestMechanism(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* DigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulMacSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulMacSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulMacSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulMacSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulKeySizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulKeySizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulKeySizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulKeySizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulIVSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulIVSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulIVSizeInBits(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulIVSizeInBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_ulSequenceNumber(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulSequenceNumber) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_ulSequenceNumber(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* ulSequenceNumber) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_bIsExport(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* bIsExport) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_bIsExport(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* bIsExport) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_RandomInfo(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_RandomInfo(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* RandomInfo) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_get_pReturnedKeyMaterial(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* pReturnedKeyMaterial) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_wtls_key_mat_params_set_pReturnedKeyMaterial(Crypt__PKCS11__CK_WTLS_KEY_MAT_PARAMS* object, SV* pReturnedKeyMaterial) {
    return CKR_OK;
}

Crypt__PKCS11__CK_CMS_SIG_PARAMS* crypt_pkcs11_ck_cms_sig_params_new(const char* class) {
    Crypt__PKCS11__CK_CMS_SIG_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_CMS_SIG_PARAMS));
    return object;
}

void crypt_pkcs11_ck_cms_sig_params_DESTROY(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_certificateHandle(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* certificateHandle) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_certificateHandle(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* certificateHandle) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pSigningMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pSigningMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pSigningMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pSigningMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pDigestMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pDigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pDigestMechanism(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pDigestMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pContentType(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pContentType) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pContentType(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pContentType) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pRequestedAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pRequestedAttributes) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pRequestedAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pRequestedAttributes) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_get_pRequiredAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pRequiredAttributes) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_cms_sig_params_set_pRequiredAttributes(Crypt__PKCS11__CK_CMS_SIG_PARAMS* object, SV* pRequiredAttributes) {
    return CKR_OK;
}

Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* crypt_pkcs11_ck_key_derivation_string_data_new(const char* class) {
    Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object = calloc(1, sizeof(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA));
    return object;
}

void crypt_pkcs11_ck_key_derivation_string_data_DESTROY(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_get_pData(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* pData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_set_pData(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* pData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_get_ulLen(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* ulLen) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_key_derivation_string_data_set_ulLen(Crypt__PKCS11__CK_KEY_DERIVATION_STRING_DATA* object, SV* ulLen) {
    return CKR_OK;
}

Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* crypt_pkcs11_ck_pkcs5_pbkd2_params_new(const char* class) {
    Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS));
    return object;
}

void crypt_pkcs11_ck_pkcs5_pbkd2_params_DESTROY(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_saltSource(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* saltSource) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_saltSource(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* saltSource) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pSaltSourceData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* pSaltSourceData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pSaltSourceData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* pSaltSourceData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_iterations(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* iterations) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_iterations(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* iterations) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_prf(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* prf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_prf(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* prf) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPrfData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* pPrfData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPrfData(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* pPrfData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPassword(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* pPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPassword(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* pPassword) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_get_ulPasswordLen(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* ulPasswordLen) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_pkcs5_pbkd2_params_set_ulPasswordLen(Crypt__PKCS11__CK_PKCS5_PBKD2_PARAMS* object, SV* ulPasswordLen) {
    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAM* crypt_pkcs11_ck_otp_param_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAM* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAM));
    return object;
}

void crypt_pkcs11_ck_otp_param_DESTROY(Crypt__PKCS11__CK_OTP_PARAM* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_otp_param_get_type(Crypt__PKCS11__CK_OTP_PARAM* object, SV* type) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_set_type(Crypt__PKCS11__CK_OTP_PARAM* object, SV* type) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_get_pValue(Crypt__PKCS11__CK_OTP_PARAM* object, SV* pValue) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_param_set_pValue(Crypt__PKCS11__CK_OTP_PARAM* object, SV* pValue) {
    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_PARAMS* crypt_pkcs11_ck_otp_params_new(const char* class) {
    Crypt__PKCS11__CK_OTP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_PARAMS));
    return object;
}

void crypt_pkcs11_ck_otp_params_DESTROY(Crypt__PKCS11__CK_OTP_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_otp_params_get_pParams(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* pParams) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_params_set_pParams(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* pParams) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_params_get_ulCount(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* ulCount) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_params_set_ulCount(Crypt__PKCS11__CK_OTP_PARAMS* object, SV* ulCount) {
    return CKR_OK;
}

Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* crypt_pkcs11_ck_otp_signature_info_new(const char* class) {
    Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object = calloc(1, sizeof(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO));
    return object;
}

void crypt_pkcs11_ck_otp_signature_info_DESTROY(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_otp_signature_info_get_pParams(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* pParams) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_signature_info_set_pParams(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* pParams) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_signature_info_get_ulCount(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* ulCount) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_otp_signature_info_set_ulCount(Crypt__PKCS11__CK_OTP_SIGNATURE_INFO* object, SV* ulCount) {
    return CKR_OK;
}

Crypt__PKCS11__CK_KIP_PARAMS* crypt_pkcs11_ck_kip_params_new(const char* class) {
    Crypt__PKCS11__CK_KIP_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_KIP_PARAMS));
    return object;
}

void crypt_pkcs11_ck_kip_params_DESTROY(Crypt__PKCS11__CK_KIP_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_kip_params_get_pMechanism(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* pMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_pMechanism(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* pMechanism) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_get_hKey(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* hKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_hKey(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* hKey) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_get_pSeed(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* pSeed) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_kip_params_set_pSeed(Crypt__PKCS11__CK_KIP_PARAMS* object, SV* pSeed) {
    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CTR_PARAMS* crypt_pkcs11_ck_aes_ctr_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CTR_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_CTR_PARAMS));
    return object;
}

void crypt_pkcs11_ck_aes_ctr_params_DESTROY(Crypt__PKCS11__CK_AES_CTR_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_get_ulCounterBits(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* ulCounterBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_set_ulCounterBits(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* ulCounterBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_get_cb(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* cb) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ctr_params_set_cb(Crypt__PKCS11__CK_AES_CTR_PARAMS* object, SV* cb) {
    return CKR_OK;
}

Crypt__PKCS11__CK_AES_GCM_PARAMS* crypt_pkcs11_ck_aes_gcm_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_GCM_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_GCM_PARAMS));
    return object;
}

void crypt_pkcs11_ck_aes_gcm_params_DESTROY(Crypt__PKCS11__CK_AES_GCM_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_pIv(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* pIv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_pIv(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* pIv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_ulIvBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* ulIvBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_ulIvBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* ulIvBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_pAAD(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* pAAD) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_pAAD(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* pAAD) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_get_ulTagBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* ulTagBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_gcm_params_set_ulTagBits(Crypt__PKCS11__CK_AES_GCM_PARAMS* object, SV* ulTagBits) {
    return CKR_OK;
}

Crypt__PKCS11__CK_AES_CCM_PARAMS* crypt_pkcs11_ck_aes_ccm_params_new(const char* class) {
    Crypt__PKCS11__CK_AES_CCM_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_AES_CCM_PARAMS));
    return object;
}

void crypt_pkcs11_ck_aes_ccm_params_DESTROY(Crypt__PKCS11__CK_AES_CCM_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_get_pNonce(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* pNonce) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_set_pNonce(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* pNonce) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_get_pAAD(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* pAAD) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aes_ccm_params_set_pAAD(Crypt__PKCS11__CK_AES_CCM_PARAMS* object, SV* pAAD) {
    return CKR_OK;
}

Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* crypt_pkcs11_ck_camellia_ctr_params_new(const char* class) {
    Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS));
    return object;
}

void crypt_pkcs11_ck_camellia_ctr_params_DESTROY(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_get_ulCounterBits(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* ulCounterBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_set_ulCounterBits(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* ulCounterBits) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_get_cb(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* cb) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_ctr_params_set_cb(Crypt__PKCS11__CK_CAMELLIA_CTR_PARAMS* object, SV* cb) {
    return CKR_OK;
}

Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS));
    return object;
}

void crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* crypt_pkcs11_ck_aria_cbc_encrypt_data_params_new(const char* class) {
    Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object = calloc(1, sizeof(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS));
    return object;
}

void crypt_pkcs11_ck_aria_cbc_encrypt_data_params_DESTROY(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object) {
    free(object);
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_iv(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_iv(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* iv) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_pData(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

CK_RV crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_pData(Crypt__PKCS11__CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object, SV* pData) {
    return CKR_OK;
}

