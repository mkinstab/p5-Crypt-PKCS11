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

MODULE = Crypt::PKCS11::CK_VERSION  PACKAGE = Crypt::PKCS11::CK_VERSION  PREFIX = crypt_pkcs11_ck_version_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_VERSION*
crypt_pkcs11_ck_version_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_VERSION  PACKAGE = Crypt::PKCS11::CK_VERSIONPtr  PREFIX = crypt_pkcs11_ck_version_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_version_DESTROY(object)
    Crypt::PKCS11::CK_VERSION* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_version_toBytes(object)
    Crypt::PKCS11::CK_VERSION* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_version_fromBytes(object, sv)
    Crypt::PKCS11::CK_VERSION* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_version_get_major(object, sv)
    Crypt::PKCS11::CK_VERSION* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_version_major(object)
    Crypt::PKCS11::CK_VERSION* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_version_get_major(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_version_set_major(object, sv)
    Crypt::PKCS11::CK_VERSION* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_version_get_minor(object, sv)
    Crypt::PKCS11::CK_VERSION* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_version_minor(object)
    Crypt::PKCS11::CK_VERSION* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_version_get_minor(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_version_set_minor(object, sv)
    Crypt::PKCS11::CK_VERSION* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_MECHANISM  PACKAGE = Crypt::PKCS11::CK_MECHANISM  PREFIX = crypt_pkcs11_ck_mechanism_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_MECHANISM*
crypt_pkcs11_ck_mechanism_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_MECHANISM  PACKAGE = Crypt::PKCS11::CK_MECHANISMPtr  PREFIX = crypt_pkcs11_ck_mechanism_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_mechanism_DESTROY(object)
    Crypt::PKCS11::CK_MECHANISM* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_mechanism_toBytes(object)
    Crypt::PKCS11::CK_MECHANISM* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_mechanism_fromBytes(object, sv)
    Crypt::PKCS11::CK_MECHANISM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_mechanism_get_mechanism(object, sv)
    Crypt::PKCS11::CK_MECHANISM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_mechanism_mechanism(object)
    Crypt::PKCS11::CK_MECHANISM* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_mechanism_get_mechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_mechanism_set_mechanism(object, sv)
    Crypt::PKCS11::CK_MECHANISM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_mechanism_get_pParameter(object, sv)
    Crypt::PKCS11::CK_MECHANISM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_mechanism_pParameter(object)
    Crypt::PKCS11::CK_MECHANISM* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_mechanism_get_pParameter(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_mechanism_set_pParameter(object, sv)
    Crypt::PKCS11::CK_MECHANISM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS  PACKAGE = Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS  PREFIX = crypt_pkcs11_ck_rsa_pkcs_oaep_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS*
crypt_pkcs11_ck_rsa_pkcs_oaep_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS  PACKAGE = Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rsa_pkcs_oaep_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rsa_pkcs_oaep_params_DESTROY(object)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rsa_pkcs_oaep_params_toBytes(object)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_hashAlg(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_oaep_params_hashAlg(object)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_hashAlg(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_hashAlg(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_mgf(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_oaep_params_mgf(object)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_mgf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_mgf(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_source(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_oaep_params_source(object)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_source(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_source(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_pSourceData(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_oaep_params_pSourceData(object)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_oaep_params_get_pSourceData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_oaep_params_set_pSourceData(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS  PACKAGE = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS  PREFIX = crypt_pkcs11_ck_rsa_pkcs_pss_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS*
crypt_pkcs11_ck_rsa_pkcs_pss_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS  PACKAGE = Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rsa_pkcs_pss_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rsa_pkcs_pss_params_DESTROY(object)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rsa_pkcs_pss_params_toBytes(object)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_get_hashAlg(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_pss_params_hashAlg(object)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_pss_params_get_hashAlg(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_set_hashAlg(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_get_mgf(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_pss_params_mgf(object)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_pss_params_get_mgf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_set_mgf(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_get_sLen(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rsa_pkcs_pss_params_sLen(object)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rsa_pkcs_pss_params_get_sLen(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rsa_pkcs_pss_params_set_sLen(object, sv)
    Crypt::PKCS11::CK_RSA_PKCS_PSS_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_ecdh1_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS*
crypt_pkcs11_ck_ecdh1_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_ecdh1_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ecdh1_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ecdh1_derive_params_toBytes(object)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_get_kdf(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh1_derive_params_kdf(object)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh1_derive_params_get_kdf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_set_kdf(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_get_pSharedData(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh1_derive_params_pSharedData(object)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh1_derive_params_get_pSharedData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_set_pSharedData(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh1_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh1_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh1_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_ECDH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_ecdh2_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS*
crypt_pkcs11_ck_ecdh2_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_ecdh2_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ecdh2_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ecdh2_derive_params_toBytes(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_get_kdf(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh2_derive_params_kdf(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh2_derive_params_get_kdf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_set_kdf(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_get_pSharedData(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh2_derive_params_pSharedData(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh2_derive_params_get_pSharedData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_set_pSharedData(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh2_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_get_hPrivateData(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh2_derive_params_hPrivateData(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh2_derive_params_get_hPrivateData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_set_hPrivateData(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData2(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecdh2_derive_params_pPublicData2(object)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecdh2_derive_params_get_pPublicData2(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecdh2_derive_params_set_pPublicData2(object, sv)
    Crypt::PKCS11::CK_ECDH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_ecmqv_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS*
crypt_pkcs11_ck_ecmqv_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_ecmqv_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ecmqv_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ecmqv_derive_params_toBytes(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_get_kdf(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecmqv_derive_params_kdf(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecmqv_derive_params_get_kdf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_set_kdf(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_get_pSharedData(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecmqv_derive_params_pSharedData(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecmqv_derive_params_get_pSharedData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_set_pSharedData(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecmqv_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_get_hPrivateData(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecmqv_derive_params_hPrivateData(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecmqv_derive_params_get_hPrivateData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_set_hPrivateData(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData2(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecmqv_derive_params_pPublicData2(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecmqv_derive_params_get_pPublicData2(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_set_pPublicData2(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_get_publicKey(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ecmqv_derive_params_publicKey(object)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ecmqv_derive_params_get_publicKey(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ecmqv_derive_params_set_publicKey(object, sv)
    Crypt::PKCS11::CK_ECMQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_x9_42_dh1_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS*
crypt_pkcs11_ck_x9_42_dh1_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_x9_42_dh1_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_x9_42_dh1_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_x9_42_dh1_derive_params_toBytes(object)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_get_kdf(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh1_derive_params_kdf(object)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh1_derive_params_get_kdf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_set_kdf(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pOtherInfo(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh1_derive_params_pOtherInfo(object)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pOtherInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pOtherInfo(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh1_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh1_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh1_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_X9_42_DH1_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_x9_42_dh2_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS*
crypt_pkcs11_ck_x9_42_dh2_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_x9_42_dh2_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_x9_42_dh2_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_x9_42_dh2_derive_params_toBytes(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_get_kdf(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh2_derive_params_kdf(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh2_derive_params_get_kdf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_set_kdf(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pOtherInfo(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh2_derive_params_pOtherInfo(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pOtherInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pOtherInfo(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh2_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_get_hPrivateData(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh2_derive_params_hPrivateData(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh2_derive_params_get_hPrivateData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_set_hPrivateData(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData2(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_dh2_derive_params_pPublicData2(object)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_dh2_derive_params_get_pPublicData2(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_dh2_derive_params_set_pPublicData2(object, sv)
    Crypt::PKCS11::CK_X9_42_DH2_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_x9_42_mqv_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS*
crypt_pkcs11_ck_x9_42_mqv_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_x9_42_mqv_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_x9_42_mqv_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_toBytes(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_get_kdf(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_kdf(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_mqv_derive_params_get_kdf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_set_kdf(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pOtherInfo(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_pOtherInfo(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pOtherInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pOtherInfo(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_get_hPrivateData(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_hPrivateData(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_mqv_derive_params_get_hPrivateData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_set_hPrivateData(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData2(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_pPublicData2(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_mqv_derive_params_get_pPublicData2(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_set_pPublicData2(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_get_publicKey(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_x9_42_mqv_derive_params_publicKey(object)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_x9_42_mqv_derive_params_get_publicKey(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_x9_42_mqv_derive_params_set_publicKey(object, sv)
    Crypt::PKCS11::CK_X9_42_MQV_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KEA_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_KEA_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_kea_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_KEA_DERIVE_PARAMS*
crypt_pkcs11_ck_kea_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KEA_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_KEA_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_kea_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_kea_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_kea_derive_params_toBytes(object)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_get_isSender(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_kea_derive_params_isSender(object)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_kea_derive_params_get_isSender(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_set_isSender(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_get_pRandomA(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_kea_derive_params_pRandomA(object)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_kea_derive_params_get_pRandomA(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_set_pRandomA(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_get_pRandomB(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_kea_derive_params_pRandomB(object)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_kea_derive_params_get_pRandomB(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_set_pRandomB(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_kea_derive_params_pPublicData(object)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_kea_derive_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kea_derive_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_KEA_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC2_CBC_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC2_CBC_PARAMS  PREFIX = crypt_pkcs11_ck_rc2_cbc_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RC2_CBC_PARAMS*
crypt_pkcs11_ck_rc2_cbc_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC2_CBC_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC2_CBC_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rc2_cbc_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rc2_cbc_params_DESTROY(object)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rc2_cbc_params_toBytes(object)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_cbc_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_cbc_params_get_ulEffectiveBits(object, sv)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc2_cbc_params_ulEffectiveBits(object)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc2_cbc_params_get_ulEffectiveBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_cbc_params_set_ulEffectiveBits(object, sv)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_cbc_params_get_iv(object, sv)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc2_cbc_params_iv(object)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc2_cbc_params_get_iv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_cbc_params_set_iv(object, sv)
    Crypt::PKCS11::CK_RC2_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS  PREFIX = crypt_pkcs11_ck_rc2_mac_general_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS*
crypt_pkcs11_ck_rc2_mac_general_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rc2_mac_general_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rc2_mac_general_params_DESTROY(object)
    Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rc2_mac_general_params_toBytes(object)
    Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_mac_general_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_mac_general_params_get_ulEffectiveBits(object, sv)
    Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc2_mac_general_params_ulEffectiveBits(object)
    Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc2_mac_general_params_get_ulEffectiveBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc2_mac_general_params_set_ulEffectiveBits(object, sv)
    Crypt::PKCS11::CK_RC2_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC5_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC5_PARAMS  PREFIX = crypt_pkcs11_ck_rc5_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RC5_PARAMS*
crypt_pkcs11_ck_rc5_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC5_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC5_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rc5_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rc5_params_DESTROY(object)
    Crypt::PKCS11::CK_RC5_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rc5_params_toBytes(object)
    Crypt::PKCS11::CK_RC5_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RC5_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_params_get_ulWordsize(object, sv)
    Crypt::PKCS11::CK_RC5_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_params_ulWordsize(object)
    Crypt::PKCS11::CK_RC5_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_params_get_ulWordsize(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_params_set_ulWordsize(object, sv)
    Crypt::PKCS11::CK_RC5_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_params_get_ulRounds(object, sv)
    Crypt::PKCS11::CK_RC5_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_params_ulRounds(object)
    Crypt::PKCS11::CK_RC5_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_params_get_ulRounds(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_params_set_ulRounds(object, sv)
    Crypt::PKCS11::CK_RC5_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC5_CBC_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC5_CBC_PARAMS  PREFIX = crypt_pkcs11_ck_rc5_cbc_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RC5_CBC_PARAMS*
crypt_pkcs11_ck_rc5_cbc_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC5_CBC_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC5_CBC_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rc5_cbc_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rc5_cbc_params_DESTROY(object)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rc5_cbc_params_toBytes(object)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_get_ulWordsize(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_cbc_params_ulWordsize(object)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_cbc_params_get_ulWordsize(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_set_ulWordsize(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_get_ulRounds(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_cbc_params_ulRounds(object)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_cbc_params_get_ulRounds(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_set_ulRounds(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_get_pIv(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_cbc_params_pIv(object)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_cbc_params_get_pIv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_cbc_params_set_pIv(object, sv)
    Crypt::PKCS11::CK_RC5_CBC_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS  PREFIX = crypt_pkcs11_ck_rc5_mac_general_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS*
crypt_pkcs11_ck_rc5_mac_general_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS  PACKAGE = Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMSPtr  PREFIX = crypt_pkcs11_ck_rc5_mac_general_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_rc5_mac_general_params_DESTROY(object)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_rc5_mac_general_params_toBytes(object)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_mac_general_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_mac_general_params_get_ulWordsize(object, sv)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_mac_general_params_ulWordsize(object)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_mac_general_params_get_ulWordsize(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_mac_general_params_set_ulWordsize(object, sv)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_mac_general_params_get_ulRounds(object, sv)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_rc5_mac_general_params_ulRounds(object)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_rc5_mac_general_params_get_ulRounds(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_rc5_mac_general_params_set_ulRounds(object, sv)
    Crypt::PKCS11::CK_RC5_MAC_GENERAL_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS  PREFIX = crypt_pkcs11_ck_des_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS*
crypt_pkcs11_ck_des_cbc_encrypt_data_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMSPtr  PREFIX = crypt_pkcs11_ck_des_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_des_cbc_encrypt_data_params_DESTROY(object)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_des_cbc_encrypt_data_params_toBytes(object)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_des_cbc_encrypt_data_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_iv(object, sv)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_des_cbc_encrypt_data_params_iv(object)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_iv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_iv(object, sv)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_pData(object, sv)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_des_cbc_encrypt_data_params_pData(object)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_des_cbc_encrypt_data_params_get_pData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_des_cbc_encrypt_data_params_set_pData(object, sv)
    Crypt::PKCS11::CK_DES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS  PREFIX = crypt_pkcs11_ck_aes_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS*
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMSPtr  PREFIX = crypt_pkcs11_ck_aes_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_DESTROY(object)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_toBytes(object)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_iv(object, sv)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_iv(object)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_iv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_iv(object, sv)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_pData(object, sv)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_pData(object)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_cbc_encrypt_data_params_get_pData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_cbc_encrypt_data_params_set_pData(object, sv)
    Crypt::PKCS11::CK_AES_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS  PACKAGE = Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS  PREFIX = crypt_pkcs11_ck_skipjack_private_wrap_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS*
crypt_pkcs11_ck_skipjack_private_wrap_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS  PACKAGE = Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMSPtr  PREFIX = crypt_pkcs11_ck_skipjack_private_wrap_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_skipjack_private_wrap_params_DESTROY(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_toBytes(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPassword(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_pPassword(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPassword(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPassword(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPublicData(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_pPublicData(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPublicData(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_get_pRandomA(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_pRandomA(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_private_wrap_params_get_pRandomA(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_set_pRandomA(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPrimeP(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_pPrimeP(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_private_wrap_params_get_pPrimeP(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_set_pPrimeP(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_get_pBaseG(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_pBaseG(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_private_wrap_params_get_pBaseG(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_set_pBaseG(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_get_pSubprimeQ(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_private_wrap_params_pSubprimeQ(object)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_private_wrap_params_get_pSubprimeQ(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_private_wrap_params_set_pSubprimeQ(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_PRIVATE_WRAP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS  PACKAGE = Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS  PREFIX = crypt_pkcs11_ck_skipjack_relayx_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS*
crypt_pkcs11_ck_skipjack_relayx_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS  PACKAGE = Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMSPtr  PREFIX = crypt_pkcs11_ck_skipjack_relayx_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_skipjack_relayx_params_DESTROY(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_skipjack_relayx_params_toBytes(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pOldWrappedX(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pOldWrappedX(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pOldWrappedX(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pOldWrappedX(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPassword(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pOldPassword(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPassword(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPassword(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPublicData(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pOldPublicData(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pOldPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pOldPublicData(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pOldRandomA(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pOldRandomA(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pOldRandomA(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pOldRandomA(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPassword(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pNewPassword(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPassword(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPassword(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPublicData(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pNewPublicData(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pNewPublicData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pNewPublicData(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_get_pNewRandomA(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_skipjack_relayx_params_pNewRandomA(object)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_skipjack_relayx_params_get_pNewRandomA(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_skipjack_relayx_params_set_pNewRandomA(object, sv)
    Crypt::PKCS11::CK_SKIPJACK_RELAYX_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_PBE_PARAMS  PACKAGE = Crypt::PKCS11::CK_PBE_PARAMS  PREFIX = crypt_pkcs11_ck_pbe_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_PBE_PARAMS*
crypt_pkcs11_ck_pbe_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_PBE_PARAMS  PACKAGE = Crypt::PKCS11::CK_PBE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_pbe_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_pbe_params_DESTROY(object)
    Crypt::PKCS11::CK_PBE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_pbe_params_toBytes(object)
    Crypt::PKCS11::CK_PBE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_get_pInitVector(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pbe_params_pInitVector(object)
    Crypt::PKCS11::CK_PBE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pbe_params_get_pInitVector(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_set_pInitVector(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_get_pPassword(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pbe_params_pPassword(object)
    Crypt::PKCS11::CK_PBE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pbe_params_get_pPassword(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_set_pPassword(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_get_pSalt(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pbe_params_pSalt(object)
    Crypt::PKCS11::CK_PBE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pbe_params_get_pSalt(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_set_pSalt(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_get_ulIteration(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pbe_params_ulIteration(object)
    Crypt::PKCS11::CK_PBE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pbe_params_get_ulIteration(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pbe_params_set_ulIteration(object, sv)
    Crypt::PKCS11::CK_PBE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS  PACKAGE = Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS  PREFIX = crypt_pkcs11_ck_key_wrap_set_oaep_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS*
crypt_pkcs11_ck_key_wrap_set_oaep_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS  PACKAGE = Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMSPtr  PREFIX = crypt_pkcs11_ck_key_wrap_set_oaep_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_key_wrap_set_oaep_params_DESTROY(object)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_key_wrap_set_oaep_params_toBytes(object)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_wrap_set_oaep_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_wrap_set_oaep_params_get_bBC(object, sv)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_key_wrap_set_oaep_params_bBC(object)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_key_wrap_set_oaep_params_get_bBC(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_wrap_set_oaep_params_set_bBC(object, sv)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_wrap_set_oaep_params_get_pX(object, sv)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_key_wrap_set_oaep_params_pX(object)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_key_wrap_set_oaep_params_get_pX(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_wrap_set_oaep_params_set_pX(object, sv)
    Crypt::PKCS11::CK_KEY_WRAP_SET_OAEP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_RANDOM_DATA  PACKAGE = Crypt::PKCS11::CK_SSL3_RANDOM_DATA  PREFIX = crypt_pkcs11_ck_ssl3_random_data_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_SSL3_RANDOM_DATA*
crypt_pkcs11_ck_ssl3_random_data_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_RANDOM_DATA  PACKAGE = Crypt::PKCS11::CK_SSL3_RANDOM_DATAPtr  PREFIX = crypt_pkcs11_ck_ssl3_random_data_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ssl3_random_data_DESTROY(object)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ssl3_random_data_toBytes(object)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_random_data_fromBytes(object, sv)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_random_data_get_pClientRandom(object, sv)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_random_data_pClientRandom(object)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_random_data_get_pClientRandom(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_random_data_set_pClientRandom(object, sv)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_random_data_get_pServerRandom(object, sv)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_random_data_pServerRandom(object)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_random_data_get_pServerRandom(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_random_data_set_pServerRandom(object, sv)
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_ssl3_master_key_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS*
crypt_pkcs11_ck_ssl3_master_key_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_ssl3_master_key_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ssl3_master_key_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ssl3_master_key_derive_params_toBytes(object)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_master_key_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_master_key_derive_params_get_RandomInfo(object, sv)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_SSL3_RANDOM_DATA*
crypt_pkcs11_ck_ssl3_master_key_derive_params_RandomInfo(object)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_ssl3_random_data_new("Crypt::PKCS11::CK_SSL3_RANDOM_DATA");
    crypt_pkcs11_ck_ssl3_master_key_derive_params_get_RandomInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_master_key_derive_params_set_RandomInfo(object, sv)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_master_key_derive_params_get_pVersion(object, sv)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
    Crypt::PKCS11::CK_VERSION* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_VERSION*
crypt_pkcs11_ck_ssl3_master_key_derive_params_pVersion(object)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_version_new("Crypt::PKCS11::CK_VERSION");
    crypt_pkcs11_ck_ssl3_master_key_derive_params_get_pVersion(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_master_key_derive_params_set_pVersion(object, sv)
    Crypt::PKCS11::CK_SSL3_MASTER_KEY_DERIVE_PARAMS* object
    Crypt::PKCS11::CK_VERSION* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT  PACKAGE = Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT  PREFIX = crypt_pkcs11_ck_ssl3_key_mat_out_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT*
crypt_pkcs11_ck_ssl3_key_mat_out_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT  PACKAGE = Crypt::PKCS11::CK_SSL3_KEY_MAT_OUTPtr  PREFIX = crypt_pkcs11_ck_ssl3_key_mat_out_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ssl3_key_mat_out_DESTROY(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_toBytes(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_fromBytes(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientMacSecret(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_hClientMacSecret(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientMacSecret(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_set_hClientMacSecret(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerMacSecret(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_hServerMacSecret(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerMacSecret(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_set_hServerMacSecret(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientKey(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_hClientKey(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_out_get_hClientKey(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_set_hClientKey(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerKey(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_hServerKey(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_out_get_hServerKey(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_set_hServerKey(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVClient(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_pIVClient(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVClient(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVClient(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVServer(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_out_pIVServer(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_out_get_pIVServer(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_out_set_pIVServer(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS  PACKAGE = Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS  PREFIX = crypt_pkcs11_ck_ssl3_key_mat_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS*
crypt_pkcs11_ck_ssl3_key_mat_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS  PACKAGE = Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMSPtr  PREFIX = crypt_pkcs11_ck_ssl3_key_mat_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_ssl3_key_mat_params_DESTROY(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_ssl3_key_mat_params_toBytes(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_get_ulMacSizeInBits(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_params_ulMacSizeInBits(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_params_get_ulMacSizeInBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_set_ulMacSizeInBits(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_get_ulKeySizeInBits(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_params_ulKeySizeInBits(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_params_get_ulKeySizeInBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_set_ulKeySizeInBits(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_get_ulIVSizeInBits(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_params_ulIVSizeInBits(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_params_get_ulIVSizeInBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_set_ulIVSizeInBits(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_get_bIsExport(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_ssl3_key_mat_params_bIsExport(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_ssl3_key_mat_params_get_bIsExport(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_set_bIsExport(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_get_RandomInfo(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_SSL3_RANDOM_DATA*
crypt_pkcs11_ck_ssl3_key_mat_params_RandomInfo(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_ssl3_random_data_new("Crypt::PKCS11::CK_SSL3_RANDOM_DATA");
    crypt_pkcs11_ck_ssl3_key_mat_params_get_RandomInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_set_RandomInfo(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    Crypt::PKCS11::CK_SSL3_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_ssl3_key_mat_params_get_pReturnedKeyMaterial(object, sv)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
    Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT*
crypt_pkcs11_ck_ssl3_key_mat_params_pReturnedKeyMaterial(object)
    Crypt::PKCS11::CK_SSL3_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_ssl3_key_mat_out_new("Crypt::PKCS11::CK_SSL3_KEY_MAT_OUT");
    crypt_pkcs11_ck_ssl3_key_mat_params_get_pReturnedKeyMaterial(object, RETVAL);
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_TLS_PRF_PARAMS  PACKAGE = Crypt::PKCS11::CK_TLS_PRF_PARAMS  PREFIX = crypt_pkcs11_ck_tls_prf_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_TLS_PRF_PARAMS*
crypt_pkcs11_ck_tls_prf_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_TLS_PRF_PARAMS  PACKAGE = Crypt::PKCS11::CK_TLS_PRF_PARAMSPtr  PREFIX = crypt_pkcs11_ck_tls_prf_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_tls_prf_params_DESTROY(object)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_tls_prf_params_toBytes(object)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_get_pSeed(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_tls_prf_params_pSeed(object)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_tls_prf_params_get_pSeed(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_set_pSeed(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_get_pLabel(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_tls_prf_params_pLabel(object)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_tls_prf_params_get_pLabel(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_set_pLabel(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_get_pOutput(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_tls_prf_params_pOutput(object)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_tls_prf_params_get_pOutput(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_tls_prf_params_set_pOutput(object, sv)
    Crypt::PKCS11::CK_TLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_RANDOM_DATA  PACKAGE = Crypt::PKCS11::CK_WTLS_RANDOM_DATA  PREFIX = crypt_pkcs11_ck_wtls_random_data_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_WTLS_RANDOM_DATA*
crypt_pkcs11_ck_wtls_random_data_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_RANDOM_DATA  PACKAGE = Crypt::PKCS11::CK_WTLS_RANDOM_DATAPtr  PREFIX = crypt_pkcs11_ck_wtls_random_data_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_wtls_random_data_DESTROY(object)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_wtls_random_data_toBytes(object)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_random_data_fromBytes(object, sv)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_random_data_get_pClientRandom(object, sv)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_random_data_pClientRandom(object)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_random_data_get_pClientRandom(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_random_data_set_pClientRandom(object, sv)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_random_data_get_pServerRandom(object, sv)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_random_data_pServerRandom(object)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_random_data_get_pServerRandom(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_random_data_set_pServerRandom(object, sv)
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS  PREFIX = crypt_pkcs11_ck_wtls_master_key_derive_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS*
crypt_pkcs11_ck_wtls_master_key_derive_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS  PACKAGE = Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMSPtr  PREFIX = crypt_pkcs11_ck_wtls_master_key_derive_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_wtls_master_key_derive_params_DESTROY(object)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_wtls_master_key_derive_params_toBytes(object)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_get_DigestMechanism(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_master_key_derive_params_DigestMechanism(object)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_master_key_derive_params_get_DigestMechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_set_DigestMechanism(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_get_RandomInfo(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_WTLS_RANDOM_DATA*
crypt_pkcs11_ck_wtls_master_key_derive_params_RandomInfo(object)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_wtls_random_data_new("Crypt::PKCS11::CK_WTLS_RANDOM_DATA");
    crypt_pkcs11_ck_wtls_master_key_derive_params_get_RandomInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_set_RandomInfo(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_get_pVersion(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_master_key_derive_params_pVersion(object)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_master_key_derive_params_get_pVersion(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_master_key_derive_params_set_pVersion(object, sv)
    Crypt::PKCS11::CK_WTLS_MASTER_KEY_DERIVE_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_PRF_PARAMS  PACKAGE = Crypt::PKCS11::CK_WTLS_PRF_PARAMS  PREFIX = crypt_pkcs11_ck_wtls_prf_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_WTLS_PRF_PARAMS*
crypt_pkcs11_ck_wtls_prf_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_PRF_PARAMS  PACKAGE = Crypt::PKCS11::CK_WTLS_PRF_PARAMSPtr  PREFIX = crypt_pkcs11_ck_wtls_prf_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_wtls_prf_params_DESTROY(object)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_wtls_prf_params_toBytes(object)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_get_DigestMechanism(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_prf_params_DigestMechanism(object)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_prf_params_get_DigestMechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_set_DigestMechanism(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_get_pSeed(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_prf_params_pSeed(object)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_prf_params_get_pSeed(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_set_pSeed(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_get_pLabel(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_prf_params_pLabel(object)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_prf_params_get_pLabel(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_set_pLabel(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_get_pOutput(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_prf_params_pOutput(object)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_prf_params_get_pOutput(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_prf_params_set_pOutput(object, sv)
    Crypt::PKCS11::CK_WTLS_PRF_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT  PACKAGE = Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT  PREFIX = crypt_pkcs11_ck_wtls_key_mat_out_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT*
crypt_pkcs11_ck_wtls_key_mat_out_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT  PACKAGE = Crypt::PKCS11::CK_WTLS_KEY_MAT_OUTPtr  PREFIX = crypt_pkcs11_ck_wtls_key_mat_out_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_wtls_key_mat_out_DESTROY(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_wtls_key_mat_out_toBytes(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_fromBytes(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_get_hMacSecret(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_out_hMacSecret(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_out_get_hMacSecret(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_set_hMacSecret(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_get_hKey(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_out_hKey(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_out_get_hKey(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_set_hKey(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_get_pIV(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_out_pIV(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_out_get_pIV(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_out_set_pIV(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS  PACKAGE = Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS  PREFIX = crypt_pkcs11_ck_wtls_key_mat_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS*
crypt_pkcs11_ck_wtls_key_mat_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS  PACKAGE = Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMSPtr  PREFIX = crypt_pkcs11_ck_wtls_key_mat_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_wtls_key_mat_params_DESTROY(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_wtls_key_mat_params_toBytes(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_DigestMechanism(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_params_DigestMechanism(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_params_get_DigestMechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_DigestMechanism(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_ulMacSizeInBits(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_params_ulMacSizeInBits(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_params_get_ulMacSizeInBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_ulMacSizeInBits(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_ulKeySizeInBits(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_params_ulKeySizeInBits(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_params_get_ulKeySizeInBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_ulKeySizeInBits(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_ulIVSizeInBits(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_params_ulIVSizeInBits(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_params_get_ulIVSizeInBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_ulIVSizeInBits(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_ulSequenceNumber(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_params_ulSequenceNumber(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_params_get_ulSequenceNumber(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_ulSequenceNumber(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_bIsExport(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_wtls_key_mat_params_bIsExport(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_wtls_key_mat_params_get_bIsExport(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_bIsExport(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_RandomInfo(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_WTLS_RANDOM_DATA*
crypt_pkcs11_ck_wtls_key_mat_params_RandomInfo(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_wtls_random_data_new("Crypt::PKCS11::CK_WTLS_RANDOM_DATA");
    crypt_pkcs11_ck_wtls_key_mat_params_get_RandomInfo(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_set_RandomInfo(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    Crypt::PKCS11::CK_WTLS_RANDOM_DATA* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_wtls_key_mat_params_get_pReturnedKeyMaterial(object, sv)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
    Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT*
crypt_pkcs11_ck_wtls_key_mat_params_pReturnedKeyMaterial(object)
    Crypt::PKCS11::CK_WTLS_KEY_MAT_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_wtls_key_mat_out_new("Crypt::PKCS11::CK_WTLS_KEY_MAT_OUT");
    crypt_pkcs11_ck_wtls_key_mat_params_get_pReturnedKeyMaterial(object, RETVAL);
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_CMS_SIG_PARAMS  PACKAGE = Crypt::PKCS11::CK_CMS_SIG_PARAMS  PREFIX = crypt_pkcs11_ck_cms_sig_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_CMS_SIG_PARAMS*
crypt_pkcs11_ck_cms_sig_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_CMS_SIG_PARAMS  PACKAGE = Crypt::PKCS11::CK_CMS_SIG_PARAMSPtr  PREFIX = crypt_pkcs11_ck_cms_sig_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_cms_sig_params_DESTROY(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_cms_sig_params_toBytes(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_get_certificateHandle(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_cms_sig_params_certificateHandle(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_cms_sig_params_get_certificateHandle(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_set_certificateHandle(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_get_pSigningMechanism(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_MECHANISM*
crypt_pkcs11_ck_cms_sig_params_pSigningMechanism(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_mechanism_new("Crypt::PKCS11::CK_MECHANISM");
    crypt_pkcs11_ck_cms_sig_params_get_pSigningMechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_set_pSigningMechanism(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_get_pDigestMechanism(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_MECHANISM*
crypt_pkcs11_ck_cms_sig_params_pDigestMechanism(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_mechanism_new("Crypt::PKCS11::CK_MECHANISM");
    crypt_pkcs11_ck_cms_sig_params_get_pDigestMechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_set_pDigestMechanism(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_get_pContentType(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_cms_sig_params_pContentType(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_cms_sig_params_get_pContentType(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_set_pContentType(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_get_pRequestedAttributes(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_cms_sig_params_pRequestedAttributes(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_cms_sig_params_get_pRequestedAttributes(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_set_pRequestedAttributes(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_get_pRequiredAttributes(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_cms_sig_params_pRequiredAttributes(object)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_cms_sig_params_get_pRequiredAttributes(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_cms_sig_params_set_pRequiredAttributes(object, sv)
    Crypt::PKCS11::CK_CMS_SIG_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA  PACKAGE = Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA  PREFIX = crypt_pkcs11_ck_key_derivation_string_data_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA*
crypt_pkcs11_ck_key_derivation_string_data_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA  PACKAGE = Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATAPtr  PREFIX = crypt_pkcs11_ck_key_derivation_string_data_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_key_derivation_string_data_DESTROY(object)
    Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_key_derivation_string_data_toBytes(object)
    Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_derivation_string_data_fromBytes(object, sv)
    Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_derivation_string_data_get_pData(object, sv)
    Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_key_derivation_string_data_pData(object)
    Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_key_derivation_string_data_get_pData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_key_derivation_string_data_set_pData(object, sv)
    Crypt::PKCS11::CK_KEY_DERIVATION_STRING_DATA* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS  PACKAGE = Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS  PREFIX = crypt_pkcs11_ck_pkcs5_pbkd2_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS*
crypt_pkcs11_ck_pkcs5_pbkd2_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS  PACKAGE = Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMSPtr  PREFIX = crypt_pkcs11_ck_pkcs5_pbkd2_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_pkcs5_pbkd2_params_DESTROY(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_toBytes(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_get_saltSource(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_saltSource(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pkcs5_pbkd2_params_get_saltSource(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_set_saltSource(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pSaltSourceData(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_pSaltSourceData(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pSaltSourceData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pSaltSourceData(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_get_iterations(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_iterations(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pkcs5_pbkd2_params_get_iterations(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_set_iterations(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_get_prf(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_prf(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pkcs5_pbkd2_params_get_prf(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_set_prf(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPrfData(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_pPrfData(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPrfData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPrfData(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPassword(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_pkcs5_pbkd2_params_pPassword(object)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_pkcs5_pbkd2_params_get_pPassword(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_pkcs5_pbkd2_params_set_pPassword(object, sv)
    Crypt::PKCS11::CK_PKCS5_PBKD2_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_OTP_PARAM  PACKAGE = Crypt::PKCS11::CK_OTP_PARAM  PREFIX = crypt_pkcs11_ck_otp_param_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_OTP_PARAM*
crypt_pkcs11_ck_otp_param_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_OTP_PARAM  PACKAGE = Crypt::PKCS11::CK_OTP_PARAMPtr  PREFIX = crypt_pkcs11_ck_otp_param_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_otp_param_DESTROY(object)
    Crypt::PKCS11::CK_OTP_PARAM* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_otp_param_toBytes(object)
    Crypt::PKCS11::CK_OTP_PARAM* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_param_fromBytes(object, sv)
    Crypt::PKCS11::CK_OTP_PARAM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_param_get_type(object, sv)
    Crypt::PKCS11::CK_OTP_PARAM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_otp_param_type(object)
    Crypt::PKCS11::CK_OTP_PARAM* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_otp_param_get_type(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_param_set_type(object, sv)
    Crypt::PKCS11::CK_OTP_PARAM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_param_get_pValue(object, sv)
    Crypt::PKCS11::CK_OTP_PARAM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_otp_param_pValue(object)
    Crypt::PKCS11::CK_OTP_PARAM* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_otp_param_get_pValue(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_param_set_pValue(object, sv)
    Crypt::PKCS11::CK_OTP_PARAM* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_OTP_PARAMS  PACKAGE = Crypt::PKCS11::CK_OTP_PARAMS  PREFIX = crypt_pkcs11_ck_otp_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_OTP_PARAMS*
crypt_pkcs11_ck_otp_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_OTP_PARAMS  PACKAGE = Crypt::PKCS11::CK_OTP_PARAMSPtr  PREFIX = crypt_pkcs11_ck_otp_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_otp_params_DESTROY(object)
    Crypt::PKCS11::CK_OTP_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_otp_params_toBytes(object)
    Crypt::PKCS11::CK_OTP_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_OTP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_params_get_pParams(object, sv)
    Crypt::PKCS11::CK_OTP_PARAMS* object
    AV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

AV*
crypt_pkcs11_ck_otp_params_pParams(object)
    Crypt::PKCS11::CK_OTP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newAV();
    crypt_pkcs11_ck_otp_params_get_pParams(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_params_set_pParams(object, sv)
    Crypt::PKCS11::CK_OTP_PARAMS* object
    AV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_params_get_ulCount(object, sv)
    Crypt::PKCS11::CK_OTP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_otp_params_ulCount(object)
    Crypt::PKCS11::CK_OTP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_otp_params_get_ulCount(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_params_set_ulCount(object, sv)
    Crypt::PKCS11::CK_OTP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_OTP_SIGNATURE_INFO  PACKAGE = Crypt::PKCS11::CK_OTP_SIGNATURE_INFO  PREFIX = crypt_pkcs11_ck_otp_signature_info_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_OTP_SIGNATURE_INFO*
crypt_pkcs11_ck_otp_signature_info_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_OTP_SIGNATURE_INFO  PACKAGE = Crypt::PKCS11::CK_OTP_SIGNATURE_INFOPtr  PREFIX = crypt_pkcs11_ck_otp_signature_info_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_otp_signature_info_DESTROY(object)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_otp_signature_info_toBytes(object)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_signature_info_fromBytes(object, sv)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_signature_info_get_pParams(object, sv)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
    AV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

AV*
crypt_pkcs11_ck_otp_signature_info_pParams(object)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
PROTOTYPE: $
CODE:
    RETVAL = newAV();
    crypt_pkcs11_ck_otp_signature_info_get_pParams(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_signature_info_set_pParams(object, sv)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
    AV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_signature_info_get_ulCount(object, sv)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_otp_signature_info_ulCount(object)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_otp_signature_info_get_ulCount(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_otp_signature_info_set_ulCount(object, sv)
    Crypt::PKCS11::CK_OTP_SIGNATURE_INFO* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KIP_PARAMS  PACKAGE = Crypt::PKCS11::CK_KIP_PARAMS  PREFIX = crypt_pkcs11_ck_kip_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_KIP_PARAMS*
crypt_pkcs11_ck_kip_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_KIP_PARAMS  PACKAGE = Crypt::PKCS11::CK_KIP_PARAMSPtr  PREFIX = crypt_pkcs11_ck_kip_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_kip_params_DESTROY(object)
    Crypt::PKCS11::CK_KIP_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_kip_params_toBytes(object)
    Crypt::PKCS11::CK_KIP_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_get_pMechanism(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

Crypt::PKCS11::CK_MECHANISM*
crypt_pkcs11_ck_kip_params_pMechanism(object)
    Crypt::PKCS11::CK_KIP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = crypt_pkcs11_ck_mechanism_new("Crypt::PKCS11::CK_MECHANISM");
    crypt_pkcs11_ck_kip_params_get_pMechanism(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_set_pMechanism(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    Crypt::PKCS11::CK_MECHANISM* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_get_hKey(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_kip_params_hKey(object)
    Crypt::PKCS11::CK_KIP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_kip_params_get_hKey(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_set_hKey(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_get_pSeed(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_kip_params_pSeed(object)
    Crypt::PKCS11::CK_KIP_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_kip_params_get_pSeed(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_kip_params_set_pSeed(object, sv)
    Crypt::PKCS11::CK_KIP_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_CTR_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_CTR_PARAMS  PREFIX = crypt_pkcs11_ck_aes_ctr_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_AES_CTR_PARAMS*
crypt_pkcs11_ck_aes_ctr_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_CTR_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_CTR_PARAMSPtr  PREFIX = crypt_pkcs11_ck_aes_ctr_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_aes_ctr_params_DESTROY(object)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_aes_ctr_params_toBytes(object)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ctr_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ctr_params_get_ulCounterBits(object, sv)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_ctr_params_ulCounterBits(object)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_ctr_params_get_ulCounterBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ctr_params_set_ulCounterBits(object, sv)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ctr_params_get_cb(object, sv)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_ctr_params_cb(object)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_ctr_params_get_cb(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ctr_params_set_cb(object, sv)
    Crypt::PKCS11::CK_AES_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_GCM_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_GCM_PARAMS  PREFIX = crypt_pkcs11_ck_aes_gcm_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_AES_GCM_PARAMS*
crypt_pkcs11_ck_aes_gcm_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_GCM_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_GCM_PARAMSPtr  PREFIX = crypt_pkcs11_ck_aes_gcm_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_aes_gcm_params_DESTROY(object)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_aes_gcm_params_toBytes(object)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_get_pIv(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_gcm_params_pIv(object)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_gcm_params_get_pIv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_set_pIv(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_get_ulIvBits(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_gcm_params_ulIvBits(object)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_gcm_params_get_ulIvBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_set_ulIvBits(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_get_pAAD(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_gcm_params_pAAD(object)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_gcm_params_get_pAAD(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_set_pAAD(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_get_ulTagBits(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_gcm_params_ulTagBits(object)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_gcm_params_get_ulTagBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_gcm_params_set_ulTagBits(object, sv)
    Crypt::PKCS11::CK_AES_GCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_CCM_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_CCM_PARAMS  PREFIX = crypt_pkcs11_ck_aes_ccm_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_AES_CCM_PARAMS*
crypt_pkcs11_ck_aes_ccm_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_AES_CCM_PARAMS  PACKAGE = Crypt::PKCS11::CK_AES_CCM_PARAMSPtr  PREFIX = crypt_pkcs11_ck_aes_ccm_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_aes_ccm_params_DESTROY(object)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_aes_ccm_params_toBytes(object)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ccm_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ccm_params_get_pNonce(object, sv)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_ccm_params_pNonce(object)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_ccm_params_get_pNonce(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ccm_params_set_pNonce(object, sv)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ccm_params_get_pAAD(object, sv)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aes_ccm_params_pAAD(object)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aes_ccm_params_get_pAAD(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aes_ccm_params_set_pAAD(object, sv)
    Crypt::PKCS11::CK_AES_CCM_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS  PACKAGE = Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS  PREFIX = crypt_pkcs11_ck_camellia_ctr_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS*
crypt_pkcs11_ck_camellia_ctr_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS  PACKAGE = Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMSPtr  PREFIX = crypt_pkcs11_ck_camellia_ctr_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_camellia_ctr_params_DESTROY(object)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_camellia_ctr_params_toBytes(object)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_ctr_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_ctr_params_get_ulCounterBits(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_camellia_ctr_params_ulCounterBits(object)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_camellia_ctr_params_get_ulCounterBits(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_ctr_params_set_ulCounterBits(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_ctr_params_get_cb(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_camellia_ctr_params_cb(object)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_camellia_ctr_params_get_cb(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_ctr_params_set_cb(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CTR_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS  PREFIX = crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS*
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMSPtr  PREFIX = crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_DESTROY(object)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_toBytes(object)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_iv(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_iv(object)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_iv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_iv(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_pData(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_pData(object)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_get_pData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_camellia_cbc_encrypt_data_params_set_pData(object, sv)
    Crypt::PKCS11::CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS  PREFIX = crypt_pkcs11_ck_aria_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS*
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_new(class)
    const char* class
PROTOTYPE: $
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS  PACKAGE = Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMSPtr  PREFIX = crypt_pkcs11_ck_aria_cbc_encrypt_data_params_

PROTOTYPES: ENABLE

void
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_DESTROY(object)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $

SV*
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_toBytes(object)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_fromBytes(object, sv)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_iv(object, sv)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_iv(object)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_iv(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_iv(object, sv)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_pData(object, sv)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

SV*
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_pData(object)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
PROTOTYPE: $
CODE:
    RETVAL = newSV(0);
    crypt_pkcs11_ck_aria_cbc_encrypt_data_params_get_pData(object, RETVAL);
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_ck_aria_cbc_encrypt_data_params_set_pData(object, sv)
    Crypt::PKCS11::CK_ARIA_CBC_ENCRYPT_DATA_PARAMS* object
    SV* sv
PROTOTYPE: $$
OUTPUT:
    RETVAL

MODULE = Crypt::PKCS11::structs  PACKAGE = Crypt::PKCS11::structs

