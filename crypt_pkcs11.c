#include "crypt_pkcs11.h"

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

static const char __CreateMutex_str[] = "CreateMutex";
static const char __DestroyMutex_str[] = "DestroyMutex";
static const char __LockMutex_str[] = "LockMutex";
static const char __UnlockMutex_str[] = "UnlockMutex";
static const char __flags_str[] = "flags";
static const char __major_str[] = "major";
static const char __minor_str[] = "minor";
static const char __cryptokiVersion_str[] = "cryptokiVersion";
static const char __manufacturerID_str[] = "manufacturerID";
static const char __libraryDescription_str[] = "libraryDescription";
static const char __libraryVersion_str[] = "libraryVersion";
static const char __slotDescription_str[] = "slotDescription";
static const char __hardwareVersion_str[] = "hardwareVersion";
static const char __firmwareVersion_str[] = "firmwareVersion";
static const char __label_str[] = "label";
static const char __model_str[] = "model";
static const char __serialNumber_str[] = "serialNumber";
static const char __ulMaxSessionCount_str[] = "ulMaxSessionCount";
static const char __ulSessionCount_str[] = "ulSessionCount";
static const char __ulMaxRwSessionCount_str[] = "ulMaxRwSessionCount";
static const char __ulRwSessionCount_str[] = "ulRwSessionCount";
static const char __ulMaxPinLen_str[] = "ulMaxPinLen";
static const char __ulMinPinLen_str[] = "ulMinPinLen";
static const char __ulTotalPublicMemory_str[] = "ulTotalPublicMemory";
static const char __ulFreePublicMemory_str[] = "ulFreePublicMemory";
static const char __ulTotalPrivateMemory_str[] = "ulTotalPrivateMemory";
static const char __ulFreePrivateMemory_str[] = "ulFreePrivateMemory";
static const char __utcTime_str[] = "utcTime";
static const char __ulMaxKeySize_str[] = "ulMaxKeySize";
static const char __ulMinKeySize_str[] = "ulMinKeySize";
static const char __slotID_str[] = "slotID";
static const char __state_str[] = "state";
static const char __ulDeviceError_str[] = "ulDeviceError";
static const char __type_str[] = "type";
static const char __pValue_str[] = "pValue";
static const char __ulValueLen_str[] = "ulValueLen";
static const char __mechanism_str[] = "mechanism";
static const char __pParameter_str[] = "pParameter";

Crypt__PKCS11__XS* crypt_pkcs11_xs_new(void) {
    Crypt__PKCS11__XS * module = calloc(1, sizeof(Crypt__PKCS11__XS));

    return module;
}

const char* crypt_pkcs11_xs_rv2str(CK_RV rv) {
    const char* str;

    switch (rv) {
    case CKR_OK:
        str = "CKR_OK";
        break;
    case CKR_CANCEL:
        str = "CKR_CANCEL";
        break;
    case CKR_HOST_MEMORY:
        str = "CKR_HOST_MEMORY";
        break;
    case CKR_SLOT_ID_INVALID:
        str = "CKR_SLOT_ID_INVALID";
        break;
    case CKR_GENERAL_ERROR:
        str = "CKR_GENERAL_ERROR";
        break;
    case CKR_FUNCTION_FAILED:
        str = "CKR_FUNCTION_FAILED";
        break;
    case CKR_ARGUMENTS_BAD:
        str = "CKR_ARGUMENTS_BAD";
        break;
    case CKR_NO_EVENT:
        str = "CKR_NO_EVENT";
        break;
    case CKR_NEED_TO_CREATE_THREADS:
        str = "CKR_NEED_TO_CREATE_THREADS";
        break;
    case CKR_CANT_LOCK:
        str = "CKR_CANT_LOCK";
        break;
    case CKR_ATTRIBUTE_READ_ONLY:
        str = "CKR_ATTRIBUTE_READ_ONLY";
        break;
    case CKR_ATTRIBUTE_SENSITIVE:
        str = "CKR_ATTRIBUTE_SENSITIVE";
        break;
    case CKR_ATTRIBUTE_TYPE_INVALID:
        str = "CKR_ATTRIBUTE_TYPE_INVALID";
        break;
    case CKR_ATTRIBUTE_VALUE_INVALID:
        str = "CKR_ATTRIBUTE_VALUE_INVALID";
        break;
    case CKR_DATA_INVALID:
        str = "CKR_DATA_INVALID";
        break;
    case CKR_DATA_LEN_RANGE:
        str = "CKR_DATA_LEN_RANGE";
        break;
    case CKR_DEVICE_ERROR:
        str = "CKR_DEVICE_ERROR";
        break;
    case CKR_DEVICE_MEMORY:
        str = "CKR_DEVICE_MEMORY";
        break;
    case CKR_DEVICE_REMOVED:
        str = "CKR_DEVICE_REMOVED";
        break;
    case CKR_ENCRYPTED_DATA_INVALID:
        str = "CKR_ENCRYPTED_DATA_INVALID";
        break;
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
        str = "CKR_ENCRYPTED_DATA_LEN_RANGE";
        break;
    case CKR_FUNCTION_CANCELED:
        str = "CKR_FUNCTION_CANCELED";
        break;
    case CKR_FUNCTION_NOT_PARALLEL:
        str = "CKR_FUNCTION_NOT_PARALLEL";
        break;
    case CKR_FUNCTION_NOT_SUPPORTED:
        str = "CKR_FUNCTION_NOT_SUPPORTED";
        break;
    case CKR_KEY_HANDLE_INVALID:
        str = "CKR_KEY_HANDLE_INVALID";
        break;
    case CKR_KEY_SIZE_RANGE:
        str = "CKR_KEY_SIZE_RANGE";
        break;
    case CKR_KEY_TYPE_INCONSISTENT:
        str = "CKR_KEY_TYPE_INCONSISTENT";
        break;
    case CKR_KEY_NOT_NEEDED:
        str = "CKR_KEY_NOT_NEEDED";
        break;
    case CKR_KEY_CHANGED:
        str = "CKR_KEY_CHANGED";
        break;
    case CKR_KEY_NEEDED:
        str = "CKR_KEY_NEEDED";
        break;
    case CKR_KEY_INDIGESTIBLE:
        str = "CKR_KEY_INDIGESTIBLE";
        break;
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
        str = "CKR_KEY_FUNCTION_NOT_PERMITTED";
        break;
    case CKR_KEY_NOT_WRAPPABLE:
        str = "CKR_KEY_NOT_WRAPPABLE";
        break;
    case CKR_KEY_UNEXTRACTABLE:
        str = "CKR_KEY_UNEXTRACTABLE";
        break;
    case CKR_MECHANISM_INVALID:
        str = "CKR_MECHANISM_INVALID";
        break;
    case CKR_MECHANISM_PARAM_INVALID:
        str = "CKR_MECHANISM_PARAM_INVALID";
        break;
    case CKR_OBJECT_HANDLE_INVALID:
        str = "CKR_OBJECT_HANDLE_INVALID";
        break;
    case CKR_OPERATION_ACTIVE:
        str = "CKR_OPERATION_ACTIVE";
        break;
    case CKR_OPERATION_NOT_INITIALIZED:
        str = "CKR_OPERATION_NOT_INITIALIZED";
        break;
    case CKR_PIN_INCORRECT:
        str = "CKR_PIN_INCORRECT";
        break;
    case CKR_PIN_INVALID:
        str = "CKR_PIN_INVALID";
        break;
    case CKR_PIN_LEN_RANGE:
        str = "CKR_PIN_LEN_RANGE";
        break;
    case CKR_PIN_EXPIRED:
        str = "CKR_PIN_EXPIRED";
        break;
    case CKR_PIN_LOCKED:
        str = "CKR_PIN_LOCKED";
        break;
    case CKR_SESSION_CLOSED:
        str = "CKR_SESSION_CLOSED";
        break;
    case CKR_SESSION_COUNT:
        str = "CKR_SESSION_COUNT";
        break;
    case CKR_SESSION_HANDLE_INVALID:
        str = "CKR_SESSION_HANDLE_INVALID";
        break;
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        str = "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
        break;
    case CKR_SESSION_READ_ONLY:
        str = "CKR_SESSION_READ_ONLY";
        break;
    case CKR_SESSION_EXISTS:
        str = "CKR_SESSION_EXISTS";
        break;
    case CKR_SESSION_READ_ONLY_EXISTS:
        str = "CKR_SESSION_READ_ONLY_EXISTS";
        break;
    case CKR_SESSION_READ_WRITE_SO_EXISTS:
        str = "CKR_SESSION_READ_WRITE_SO_EXISTS";
        break;
    case CKR_SIGNATURE_INVALID:
        str = "CKR_SIGNATURE_INVALID";
        break;
    case CKR_SIGNATURE_LEN_RANGE:
        str = "CKR_SIGNATURE_LEN_RANGE";
        break;
    case CKR_TEMPLATE_INCOMPLETE:
        str = "CKR_TEMPLATE_INCOMPLETE";
        break;
    case CKR_TEMPLATE_INCONSISTENT:
        str = "CKR_TEMPLATE_INCONSISTENT";
        break;
    case CKR_TOKEN_NOT_PRESENT:
        str = "CKR_TOKEN_NOT_PRESENT";
        break;
    case CKR_TOKEN_NOT_RECOGNIZED:
        str = "CKR_TOKEN_NOT_RECOGNIZED";
        break;
    case CKR_TOKEN_WRITE_PROTECTED:
        str = "CKR_TOKEN_WRITE_PROTECTED";
        break;
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        str = "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
        break;
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
        str = "CKR_UNWRAPPING_KEY_SIZE_RANGE";
        break;
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        str = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
        break;
    case CKR_USER_ALREADY_LOGGED_IN:
        str = "CKR_USER_ALREADY_LOGGED_IN";
        break;
    case CKR_USER_NOT_LOGGED_IN:
        str = "CKR_USER_NOT_LOGGED_IN";
        break;
    case CKR_USER_PIN_NOT_INITIALIZED:
        str = "CKR_USER_PIN_NOT_INITIALIZED";
        break;
    case CKR_USER_TYPE_INVALID:
        str = "CKR_USER_TYPE_INVALID";
        break;
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
        str = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
        break;
    case CKR_USER_TOO_MANY_TYPES:
        str = "CKR_USER_TOO_MANY_TYPES";
        break;
    case CKR_WRAPPED_KEY_INVALID:
        str = "CKR_WRAPPED_KEY_INVALID";
        break;
    case CKR_WRAPPED_KEY_LEN_RANGE:
        str = "CKR_WRAPPED_KEY_LEN_RANGE";
        break;
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
        str = "CKR_WRAPPING_KEY_HANDLE_INVALID";
        break;
    case CKR_WRAPPING_KEY_SIZE_RANGE:
        str = "CKR_WRAPPING_KEY_SIZE_RANGE";
        break;
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        str = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
        break;
    case CKR_RANDOM_SEED_NOT_SUPPORTED:
        str = "CKR_RANDOM_SEED_NOT_SUPPORTED";
        break;
    case CKR_RANDOM_NO_RNG:
        str = "CKR_RANDOM_NO_RNG";
        break;
    case CKR_DOMAIN_PARAMS_INVALID:
        str = "CKR_DOMAIN_PARAMS_INVALID";
        break;
    case CKR_BUFFER_TOO_SMALL:
        str = "CKR_BUFFER_TOO_SMALL";
        break;
    case CKR_SAVED_STATE_INVALID:
        str = "CKR_SAVED_STATE_INVALID";
        break;
    case CKR_INFORMATION_SENSITIVE:
        str = "CKR_INFORMATION_SENSITIVE";
        break;
    case CKR_STATE_UNSAVEABLE:
        str = "CKR_STATE_UNSAVEABLE";
        break;
    case CKR_CRYPTOKI_NOT_INITIALIZED:
        str = "CKR_CRYPTOKI_NOT_INITIALIZED";
        break;
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
        str = "CKR_CRYPTOKI_ALREADY_INITIALIZED";
        break;
    case CKR_MUTEX_BAD:
        str = "CKR_MUTEX_BAD";
        break;
    case CKR_MUTEX_NOT_LOCKED:
        str = "CKR_MUTEX_NOT_LOCKED";
        break;
    case CKR_NEW_PIN_MODE:
        str = "CKR_NEW_PIN_MODE";
        break;
    case CKR_NEXT_OTP:
        str = "CKR_NEXT_OTP";
        break;
    case CKR_FUNCTION_REJECTED:
        str = "CKR_FUNCTION_REJECTED";
        break;
    case CKR_VENDOR_DEFINED:
        str = "CKR_VENDOR_DEFINED";
        break;
    default:
        str = "UNKNOWN_ERROR";
    }

    return str;
}

static SV* __CreateMutexSV = NULL_PTR;

static CK_RV __CreateMutex(CK_VOID_PTR_PTR ppMutex) {
    dSP;
    int args;
    CK_RV rv = CKR_OK;

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);

    args = call_sv(__CreateMutexSV, G_SCALAR);

    SPAGAIN;

    if (args == 1
        && !(*ppMutex = newSVsv(POPs)))
    {
        rv = CKR_GENERAL_ERROR;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return rv;
}

void crypt_pkcs11_xs_setCreateMutex(SV* pCreateMutex) {
    SvGETMAGIC(pCreateMutex);
    if (__CreateMutexSV == NULL_PTR) {
        __CreateMutexSV = newSVsv(pCreateMutex);
    }
    else {
        sv_setsv(__CreateMutexSV, pCreateMutex);
    }
}

void crypt_pkcs11_xs_clearCreateMutex(void) {
    if (__CreateMutexSV) {
        SvREFCNT_dec(__CreateMutexSV);
        __CreateMutexSV = NULL_PTR;
    }
}

static SV* __DestroyMutexSV = NULL_PTR;

static CK_RV __DestroyMutex(CK_VOID_PTR pMutex) {
    dSP;
    int args;
    CK_RV rv = CKR_GENERAL_ERROR;

    if (!pMutex) {
        return CKR_ARGUMENTS_BAD;
    }

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVsv((SV*)pMutex)));
    PUTBACK;

    args = call_sv(__DestroyMutexSV, G_SCALAR);

    SPAGAIN;

    if (args == 1) {
        rv = (CK_RV)POPl;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return rv;
}

void crypt_pkcs11_xs_setDestroyMutex(SV* pDestroyMutex) {
    SvGETMAGIC(pDestroyMutex);
    if (__DestroyMutexSV == NULL_PTR) {
        __DestroyMutexSV = newSVsv(pDestroyMutex);
    }
    else {
        sv_setsv(__DestroyMutexSV, pDestroyMutex);
    }
}

void crypt_pkcs11_xs_clearDestroyMutex(void) {
    if (__DestroyMutexSV) {
        SvREFCNT_dec(__DestroyMutexSV);
        __DestroyMutexSV = NULL_PTR;
    }
}

static SV* __LockMutexSV = NULL_PTR;

static CK_RV __LockMutex(CK_VOID_PTR pMutex) {
    dSP;
    int args;
    CK_RV rv = CKR_GENERAL_ERROR;

    if (!pMutex) {
        return CKR_ARGUMENTS_BAD;
    }

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVsv((SV*)pMutex)));
    PUTBACK;

    args = call_sv(__LockMutexSV, G_SCALAR);

    SPAGAIN;

    if (args == 1) {
        rv = (CK_RV)POPl;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return rv;
}

void crypt_pkcs11_xs_setLockMutex(SV* pLockMutex) {
    SvGETMAGIC(pLockMutex);
    if (__LockMutexSV == NULL_PTR) {
        __LockMutexSV = newSVsv(pLockMutex);
    }
    else {
        sv_setsv(__LockMutexSV, pLockMutex);
    }
}

void crypt_pkcs11_xs_clearLockMutex(void) {
    if (__LockMutexSV) {
        SvREFCNT_dec(__LockMutexSV);
        __LockMutexSV = NULL_PTR;
    }
}

static SV* __UnlockMutexSV = NULL_PTR;

static CK_RV __UnlockMutex(CK_VOID_PTR pMutex) {
    dSP;
    int args;
    CK_RV rv = CKR_GENERAL_ERROR;

    if (!pMutex) {
        return CKR_ARGUMENTS_BAD;
    }

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVsv((SV*)pMutex)));
    PUTBACK;

    args = call_sv(__UnlockMutexSV, G_SCALAR);

    SPAGAIN;

    if (args == 1) {
        rv = (CK_RV)POPl;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return rv;
}

void crypt_pkcs11_xs_setUnlockMutex(SV* pUnlockMutex) {
    SvGETMAGIC(pUnlockMutex);
    if (__UnlockMutexSV == NULL_PTR) {
        __UnlockMutexSV = newSVsv(pUnlockMutex);
    }
    else {
        sv_setsv(__UnlockMutexSV, pUnlockMutex);
    }
}

void crypt_pkcs11_xs_clearUnlockMutex(void) {
    if (__UnlockMutexSV) {
        SvREFCNT_dec(__UnlockMutexSV);
        __UnlockMutexSV = NULL_PTR;
    }
}

CK_RV crypt_pkcs11_xs_load(Crypt__PKCS11__XS* module, const char* path) {
    CK_C_GetFunctionList pGetFunctionList = NULL_PTR;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (module->handle) {
        return CKR_GENERAL_ERROR;
    }
    if (module->function_list) {
        return CKR_GENERAL_ERROR;
    }

#ifdef HAVE_DLFCN_H
    if (module->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL)) {
        pGetFunctionList = (CK_C_GetFunctionList)dlsym(module->handle, "C_GetFunctionList");
    }
#else
    return CKR_FUNCTION_FAILED;
#endif

    if (pGetFunctionList) {
        return pGetFunctionList(&(module->function_list));
    }

    return CKR_FUNCTION_FAILED;
}

CK_RV crypt_pkcs11_xs_unload(Crypt__PKCS11__XS* module) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->handle) {
        return CKR_GENERAL_ERROR;
    }

    crypt_pkcs11_xs_C_Finalize(module);

#ifdef HAVE_DLFCN_H
    if (dlclose(module->handle)) {
        return CKR_FUNCTION_FAILED;
    }
#else
    return CKR_FUNCTION_FAILED;
#endif

    module->handle = NULL_PTR;
    module->function_list = NULL_PTR;

    return CKR_OK;
}

void crypt_pkcs11_xs_DESTROY(Crypt__PKCS11__XS* module) {
    if (module) {
        if (module->handle) {
            crypt_pkcs11_xs_C_Finalize(module);
            crypt_pkcs11_xs_unload(module);
        }
        free(module);
    }
}

CK_RV crypt_pkcs11_xs_C_Initialize(Crypt__PKCS11__XS* module, HV* pInitArgs) {
    CK_C_INITIALIZE_ARGS InitArgs = { NULL_PTR, NULL_PTR, NULL_PTR, NULL_PTR, 0, NULL_PTR };
    int useInitArgs = 0;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Initialize) {
        return CKR_GENERAL_ERROR;
    }

    if (pInitArgs) {
        /*
         * Fetch all hash values even if they may not exist.
         */
        SV** CreateMutex = hv_fetch(pInitArgs, __CreateMutex_str, sizeof(__CreateMutex_str)-1, 0);
        SV** DestroyMutex = hv_fetch(pInitArgs, __DestroyMutex_str, sizeof(__DestroyMutex_str)-1, 0);
        SV** LockMutex = hv_fetch(pInitArgs, __LockMutex_str, sizeof(__LockMutex_str)-1, 0);
        SV** UnlockMutex = hv_fetch(pInitArgs, __UnlockMutex_str, sizeof(__UnlockMutex_str)-1, 0);
        SV** flags = hv_fetch(pInitArgs, __flags_str, sizeof(__flags_str)-1, 0);

        /*
         * If any of the mutex callback exists, all must exist.
         */
        if (CreateMutex || DestroyMutex || LockMutex || UnlockMutex) {
            if (!CreateMutex
                || !DestroyMutex
                || !LockMutex
                || !UnlockMutex
                || !*CreateMutex
                || !*DestroyMutex
                || !*LockMutex
                || !*UnlockMutex
                || !SvOK(*CreateMutex)
                || !SvOK(*DestroyMutex)
                || !SvOK(*LockMutex)
                || !SvOK(*UnlockMutex))
            {
                return CKR_ARGUMENTS_BAD;
            }

            crypt_pkcs11_xs_setCreateMutex(*CreateMutex);
            crypt_pkcs11_xs_setDestroyMutex(*DestroyMutex);
            crypt_pkcs11_xs_setLockMutex(*LockMutex);
            crypt_pkcs11_xs_setUnlockMutex(*UnlockMutex);

            InitArgs.CreateMutex = &__CreateMutex;
            InitArgs.DestroyMutex = &__DestroyMutex;
            InitArgs.LockMutex = &__LockMutex;
            InitArgs.UnlockMutex = &__UnlockMutex;

            useInitArgs = 1;
        }

        if (flags) {
            if (!*flags || !SvIOK(*flags))
            {
                return CKR_ARGUMENTS_BAD;
            }

            InitArgs.flags = SvUV(*flags);

            useInitArgs = 1;
        }
    }

    return module->function_list->C_Initialize(useInitArgs ? &InitArgs : NULL_PTR);
}

CK_RV crypt_pkcs11_xs_C_Finalize(Crypt__PKCS11__XS* module) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Finalize) {
        return CKR_GENERAL_ERROR;
    }

    return module->function_list->C_Finalize(NULL_PTR);
}

CK_RV crypt_pkcs11_xs_C_GetInfo(Crypt__PKCS11__XS* module, HV* pInfo) {
    CK_INFO _pInfo = {
        { 0, 0 },
        "                                ",
        0,
        "                                ",
        { 0, 0 }
    };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetInfo) {
        return CKR_GENERAL_ERROR;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = (module->function_list->C_GetInfo(&_pInfo))) == CKR_OK) {
        HV* cryptokiVersion = newHV();
        HV* libraryVersion = newHV();
        SV* manufacturerID;
        SV* libraryDescription;

        hv_store(cryptokiVersion, __major_str, sizeof(__major_str)-1, newSVuv(_pInfo.cryptokiVersion.major), 0);
        hv_store(cryptokiVersion, __minor_str, sizeof(__minor_str)-1, newSVuv(_pInfo.cryptokiVersion.minor), 0);
        hv_store(pInfo, __cryptokiVersion_str, sizeof(__cryptokiVersion_str)-1, newRV_noinc((SV*)cryptokiVersion), 0);
        hv_store(pInfo, __manufacturerID_str, sizeof(__manufacturerID_str)-1, (manufacturerID = newSVpv((char*)_pInfo.manufacturerID,32)), 0);
        hv_store(pInfo, __flags_str, sizeof(__flags_str)-1, newSVuv(_pInfo.flags), 0);
        hv_store(pInfo, __libraryDescription_str, sizeof(__libraryDescription_str)-1, (libraryDescription = newSVpv((char*)_pInfo.libraryDescription,32)), 0);
        hv_store(libraryVersion, __major_str, sizeof(__major_str)-1, newSVuv(_pInfo.libraryVersion.major), 0);
        hv_store(libraryVersion, __minor_str, sizeof(__minor_str)-1, newSVuv(_pInfo.libraryVersion.minor), 0);
        hv_store(pInfo, __libraryVersion_str, sizeof(__libraryVersion_str)-1, newRV_noinc((SV*)libraryVersion), 0);

        sv_utf8_upgrade(manufacturerID);
        sv_utf8_upgrade(libraryDescription);
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetSlotList(Crypt__PKCS11__XS* module, CK_BBOOL tokenPresent, AV* pSlotList) {
    CK_SLOT_ID_PTR _pSlotList;
    CK_ULONG ulCount, ulPos;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetSlotList) {
        return CKR_GENERAL_ERROR;
    }
    if (!pSlotList) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetSlotList(tokenPresent, NULL_PTR, &ulCount)) != CKR_OK) {
        return rv;
    }
    if (ulCount < 1) {
        return rv;
    }

    if (!(_pSlotList = calloc(ulCount, sizeof(CK_SLOT_ID)))) {
        return CKR_HOST_MEMORY;
    }
    if ((rv = module->function_list->C_GetSlotList(tokenPresent, _pSlotList, &ulCount)) != CKR_OK) {
        free(_pSlotList);
        return rv;
    }

    for (ulPos = 0; ulPos < ulCount; ulPos++) {
        av_push(pSlotList, newSVuv(_pSlotList[ulPos]));
    }
    free(_pSlotList);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetSlotInfo(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID, HV* pInfo) {
    CK_SLOT_INFO _pInfo = {
        "                                                                ",
        "                                ",
        0,
        { 0, 0 },
        { 0, 0 }
    };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetSlotInfo) {
        return CKR_GENERAL_ERROR;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetSlotInfo(slotID, &_pInfo)) == CKR_OK) {
        HV* hardwareVersion = newHV();
        HV* firmwareVersion = newHV();
        SV* slotDescription;
        SV* manufacturerID;

        hv_store(pInfo, __slotDescription_str, sizeof(__slotDescription_str)-1, (slotDescription = newSVpv((char*)_pInfo.slotDescription,64)), 0);
        hv_store(pInfo, __manufacturerID_str, sizeof(__manufacturerID_str)-1, (manufacturerID = newSVpv((char*)_pInfo.manufacturerID,32)), 0);
        hv_store(pInfo, __flags_str, sizeof(__flags_str)-1, newSVuv(_pInfo.flags), 0);
        hv_store(hardwareVersion, __major_str, sizeof(__major_str)-1, newSVuv(_pInfo.hardwareVersion.major), 0);
        hv_store(hardwareVersion, __minor_str, sizeof(__minor_str)-1, newSVuv(_pInfo.hardwareVersion.minor), 0);
        hv_store(pInfo, __hardwareVersion_str, sizeof(__hardwareVersion_str)-1, newRV_noinc((SV*)hardwareVersion), 0);
        hv_store(firmwareVersion, __major_str, sizeof(__major_str)-1, newSVuv(_pInfo.firmwareVersion.major), 0);
        hv_store(firmwareVersion, __minor_str, sizeof(__minor_str)-1, newSVuv(_pInfo.firmwareVersion.minor), 0);
        hv_store(pInfo, __firmwareVersion_str, sizeof(__firmwareVersion_str)-1, newRV_noinc((SV*)firmwareVersion), 0);

        sv_utf8_upgrade(slotDescription);
        sv_utf8_upgrade(manufacturerID);
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetTokenInfo(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID, HV* pInfo) {
    CK_TOKEN_INFO _pInfo = {
        "                                ",
        "                                ",
        "                ",
        "                ",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        { 0, 0 },
        { 0, 0 },
        "                "
    };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetTokenInfo) {
        return CKR_GENERAL_ERROR;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetTokenInfo(slotID, &_pInfo)) == CKR_OK) {
        HV* hardwareVersion = newHV();
        HV* firmwareVersion = newHV();
        SV* label;
        SV* manufacturerID;
        SV* model;
        SV* serialNumber;
        SV* utcTime;

        hv_store(pInfo, __label_str, sizeof(__label_str)-1, (label = newSVpv((char*)_pInfo.label,32)), 0);
        hv_store(pInfo, __manufacturerID_str, sizeof(__manufacturerID_str)-1, (manufacturerID = newSVpv((char*)_pInfo.manufacturerID,32)), 0);
        hv_store(pInfo, __model_str, sizeof(__model_str)-1, (model = newSVpv((char*)_pInfo.model,16)), 0);
        hv_store(pInfo, __serialNumber_str, sizeof(__serialNumber_str)-1, (serialNumber = newSVpv((char*)_pInfo.serialNumber,16)), 0);
        hv_store(pInfo, __flags_str, sizeof(__flags_str)-1, newSVuv(_pInfo.flags), 0);
        hv_store(pInfo, __ulMaxSessionCount_str, sizeof(__ulMaxSessionCount_str)-1, newSVuv(_pInfo.ulMaxSessionCount), 0);
        hv_store(pInfo, __ulSessionCount_str, sizeof(__ulSessionCount_str)-1, newSVuv(_pInfo.ulSessionCount), 0);
        hv_store(pInfo, __ulMaxRwSessionCount_str, sizeof(__ulMaxRwSessionCount_str)-1, newSVuv(_pInfo.ulMaxRwSessionCount), 0);
        hv_store(pInfo, __ulRwSessionCount_str, sizeof(__ulRwSessionCount_str)-1, newSVuv(_pInfo.ulRwSessionCount), 0);
        hv_store(pInfo, __ulMaxPinLen_str, sizeof(__ulMaxPinLen_str)-1, newSVuv(_pInfo.ulMaxPinLen), 0);
        hv_store(pInfo, __ulMinPinLen_str, sizeof(__ulMinPinLen_str)-1, newSVuv(_pInfo.ulMinPinLen), 0);
        hv_store(pInfo, __ulTotalPublicMemory_str, sizeof(__ulTotalPublicMemory_str)-1, newSVuv(_pInfo.ulTotalPublicMemory), 0);
        hv_store(pInfo, __ulFreePublicMemory_str, sizeof(__ulFreePublicMemory_str)-1, newSVuv(_pInfo.ulFreePublicMemory), 0);
        hv_store(pInfo, __ulTotalPrivateMemory_str, sizeof(__ulTotalPrivateMemory_str)-1, newSVuv(_pInfo.ulTotalPrivateMemory), 0);
        hv_store(pInfo, __ulFreePrivateMemory_str, sizeof(__ulFreePrivateMemory_str)-1, newSVuv(_pInfo.ulFreePrivateMemory), 0);
        hv_store(hardwareVersion, __major_str, sizeof(__major_str)-1, newSVuv(_pInfo.hardwareVersion.major), 0);
        hv_store(hardwareVersion, __minor_str, sizeof(__minor_str)-1, newSVuv(_pInfo.hardwareVersion.minor), 0);
        hv_store(pInfo, __hardwareVersion_str, sizeof(__hardwareVersion_str)-1, newRV_noinc((SV*)hardwareVersion), 0);
        hv_store(firmwareVersion, __major_str, sizeof(__major_str)-1, newSVuv(_pInfo.firmwareVersion.major), 0);
        hv_store(firmwareVersion, __minor_str, sizeof(__minor_str)-1, newSVuv(_pInfo.firmwareVersion.minor), 0);
        hv_store(pInfo, __firmwareVersion_str, sizeof(__firmwareVersion_str)-1, newRV_noinc((SV*)firmwareVersion), 0);
        hv_store(pInfo, __utcTime_str, sizeof(__utcTime_str)-1, (utcTime = newSVpv((char*)_pInfo.utcTime,16)), 0);

        sv_utf8_upgrade(label);
        sv_utf8_upgrade(manufacturerID);
        sv_utf8_upgrade(model);
        sv_utf8_upgrade(serialNumber);
        sv_utf8_upgrade(utcTime);
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetMechanismList(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID, AV* pMechanismList) {
    CK_MECHANISM_TYPE_PTR _pMechanismList;
    CK_ULONG ulCount, ulPos;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetMechanismList) {
        return CKR_GENERAL_ERROR;
    }
    if (!pMechanismList) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetMechanismList(slotID, NULL_PTR, &ulCount)) != CKR_OK) {
        return rv;
    }
    if (ulCount < 1) {
        return rv;
    }

    if (!(_pMechanismList = calloc(ulCount, sizeof(CK_MECHANISM_TYPE)))) {
        return CKR_HOST_MEMORY;
    }
    if ((rv = module->function_list->C_GetMechanismList(slotID, _pMechanismList, &ulCount)) != CKR_OK) {
        free(_pMechanismList);
        return rv;
    }

    for (ulPos = 0; ulPos < ulCount; ulPos++) {
        av_push(pMechanismList, newSVuv(_pMechanismList[ulPos]));
    }
    free(_pMechanismList);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetMechanismInfo(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, HV* pInfo) {
    CK_MECHANISM_INFO _pInfo = { 0, 0, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetMechanismInfo) {
        return CKR_GENERAL_ERROR;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetMechanismInfo(slotID, type, &_pInfo)) == CKR_OK) {
        hv_store(pInfo, __ulMinKeySize_str, sizeof(__ulMinKeySize_str)-1, newSVuv(_pInfo.ulMinKeySize), 0);
        hv_store(pInfo, __ulMaxKeySize_str, sizeof(__ulMaxKeySize_str)-1, newSVuv(_pInfo.ulMaxKeySize), 0);
        hv_store(pInfo, __flags_str, sizeof(__flags_str)-1, newSVuv(_pInfo.flags), 0);
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_InitToken(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID, SV* pPin, SV* pLabel) {
    CK_RV rv;
    SV* _pPin;
    SV* _pLabel;
    STRLEN len;
    STRLEN len2;
    char* _pPin2;
    char* _pLabel2;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_InitToken) {
        return CKR_GENERAL_ERROR;
    }
    if (!pPin) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pLabel) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pPin);
    if (!(_pPin = newSVsv(pPin))) {
        return CKR_GENERAL_ERROR;
    }
    SvGETMAGIC(pLabel);
    if (!(_pLabel = newSVsv(pLabel))) {
        SvREFCNT_dec(_pPin);
        return CKR_GENERAL_ERROR;
    }

    if (!sv_utf8_downgrade(_pPin, 0)
        || !sv_utf8_downgrade(_pLabel, 0)
        || !(_pPin2 = SvPV(_pPin, len))
        || !(_pLabel2 = SvPV(_pLabel, len2))
        || len2 != 32)
    {
        SvREFCNT_dec(_pPin);
        SvREFCNT_dec(_pLabel);
        return CKR_GENERAL_ERROR;
    }

    rv = module->function_list->C_InitToken(slotID, _pPin2, len, _pLabel2);
    SvREFCNT_dec(_pPin);
    SvREFCNT_dec(_pLabel);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_InitPIN(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPin) {
    CK_RV rv;
    SV* _pPin;
    STRLEN len;
    char* _pPin2;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_InitPIN) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPin) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pPin);
    if (!(_pPin = newSVsv(pPin))) {
        return CKR_GENERAL_ERROR;
    }

    if (!sv_utf8_downgrade(_pPin, 0)
        || !(_pPin2 = SvPV(_pPin, len)))
    {
        SvREFCNT_dec(_pPin);
        return CKR_GENERAL_ERROR;
    }

    rv = module->function_list->C_InitPIN(hSession, _pPin2, len);
    SvREFCNT_dec(_pPin);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_SetPIN(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pOldPin, SV* pNewPin) {
    CK_RV rv;
    SV* _pOldPin;
    STRLEN oldLen;
    char* _pOldPin2;
    SV* _pNewPin;
    STRLEN newLen;
    char* _pNewPin2;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SetPIN) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pOldPin) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pNewPin) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pOldPin);
    if (!(_pOldPin = newSVsv(pOldPin))) {
        return CKR_GENERAL_ERROR;
    }
    SvGETMAGIC(pNewPin);
    if (!(_pNewPin = newSVsv(pNewPin))) {
        SvREFCNT_dec(_pOldPin);
        return CKR_GENERAL_ERROR;
    }

    if (!sv_utf8_downgrade(_pOldPin, 0)
        || !sv_utf8_downgrade(_pNewPin, 0)
        || !(_pOldPin2 = SvPV(_pOldPin, oldLen))
        || !(_pNewPin2 = SvPV(_pNewPin, newLen)))
    {
        SvREFCNT_dec(_pOldPin);
        SvREFCNT_dec(_pNewPin);
        return CKR_GENERAL_ERROR;
    }

    rv = module->function_list->C_SetPIN(hSession, _pOldPin2, oldLen, _pNewPin2, newLen);
    SvREFCNT_dec(_pOldPin);
    SvREFCNT_dec(_pNewPin);

    return rv;
}

static CK_RV __OpenSession_Notify(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication) {
    dSP;
    int args;
    CK_RV rv = CKR_GENERAL_ERROR;

    if (!pApplication) {
        return CKR_ARGUMENTS_BAD;
    }

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVuv(hSession)));
    XPUSHs(sv_2mortal(newSVuv(event)));
    PUTBACK;

    args = call_sv((SV*)pApplication, G_SCALAR);

    SPAGAIN;

    if (args == 1) {
        rv = (CK_RV)POPl;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return rv;
}

CK_RV crypt_pkcs11_xs_C_OpenSession(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID, CK_FLAGS flags, SV* Notify, SV* phSession) {
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_OpenSession) {
        return CKR_GENERAL_ERROR;
    }
    if (!phSession) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(Notify);
    SvGETMAGIC(phSession);
    if (Notify && SvOK(Notify)) {
        if ((rv = module->function_list->C_OpenSession(slotID, flags, (CK_VOID_PTR)Notify, &__OpenSession_Notify, &hSession)) == CKR_OK) {
            sv_setuv(phSession, hSession);
            SvSETMAGIC(phSession);
        }
    }
    else {
        if ((rv = module->function_list->C_OpenSession(slotID, flags, NULL_PTR, NULL_PTR, &hSession)) == CKR_OK) {
            sv_setuv(phSession, hSession);
            SvSETMAGIC(phSession);
        }
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_CloseSession(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_CloseSession) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    return module->function_list->C_CloseSession(hSession);
}

CK_RV crypt_pkcs11_xs_C_CloseAllSessions(Crypt__PKCS11__XS* module, CK_SLOT_ID slotID) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_CloseAllSessions) {
        return CKR_GENERAL_ERROR;
    }

    return module->function_list->C_CloseAllSessions(slotID);
}

CK_RV crypt_pkcs11_xs_C_GetSessionInfo(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pInfo) {
    CK_SESSION_INFO _pInfo = { 0, 0, 0, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetSessionInfo) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pInfo) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetSessionInfo(hSession, &_pInfo)) == CKR_OK) {
        hv_store(pInfo, __slotID_str, sizeof(__slotID_str)-1, newSVuv(_pInfo.slotID), 0);
        hv_store(pInfo, __state_str, sizeof(__state_str)-1, newSVuv(_pInfo.state), 0);
        hv_store(pInfo, __flags_str, sizeof(__flags_str)-1, newSVuv(_pInfo.flags), 0);
        hv_store(pInfo, __ulDeviceError_str, sizeof(__ulDeviceError_str)-1, newSVuv(_pInfo.ulDeviceError), 0);
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetOperationState(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pOperationState) {
    CK_BYTE_PTR _pOperationState;
    CK_ULONG ulOperationStateLen = 0;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetOperationState) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pOperationState) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetOperationState(hSession, NULL_PTR, &ulOperationStateLen)) != CKR_OK) {
        return rv;
    }
    if (ulOperationStateLen < 1) {
        sv_setsv(pOperationState, &PL_sv_undef);
        return rv;
    }

    if (!(_pOperationState = calloc(ulOperationStateLen, sizeof(CK_BYTE)))) {
        return CKR_HOST_MEMORY;
    }
    if ((rv = module->function_list->C_GetOperationState(hSession, _pOperationState, &ulOperationStateLen)) != CKR_OK) {
        free(_pOperationState);
        return rv;
    }

    SvGETMAGIC(pOperationState);
    SvUTF8_off(pOperationState);
    sv_setpvn(pOperationState, _pOperationState, ulOperationStateLen * sizeof(CK_BYTE));
    SvSETMAGIC(pOperationState);
    free(_pOperationState);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_SetOperationState(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pOperationState, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
    CK_BYTE_PTR _pOperationState;
    STRLEN ulOperationStateLen;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SetOperationState) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pOperationState) {
        return CKR_ARGUMENTS_BAD;
    }
    /*
     * TODO: Should we check hEncryptionKey and/or hAuthenticationKey for
     * invalid handler?
     */

    SvGETMAGIC(pOperationState);
    if (!(_pOperationState = (CK_BYTE_PTR)SvPVbyte(pOperationState, ulOperationStateLen))) {
        return CKR_GENERAL_ERROR;
    }
    if (ulOperationStateLen < 0) {
        return CKR_GENERAL_ERROR;
    }

    /*
     * TODO: What if ulOperationStateLen is 0 ?
     */

    return module->function_list->C_SetOperationState(hSession, _pOperationState, (CK_ULONG)ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
}

CK_RV crypt_pkcs11_xs_C_Login(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, SV* pPin) {
    CK_RV rv;
    SV* _pPin;
    STRLEN len;
    char* _pPin2;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Login) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPin) {
        return CKR_GENERAL_ERROR;
    }

    SvGETMAGIC(pPin);
    if (!(_pPin = newSVsv(pPin))) {
        return CKR_GENERAL_ERROR;
    }

    if (!sv_utf8_downgrade(_pPin, 0)
        || !(_pPin2 = SvPV(_pPin, len)))
    {
        SvREFCNT_dec(_pPin);
        return CKR_GENERAL_ERROR;
    }

    rv = module->function_list->C_Login(hSession, userType, _pPin2, len);
    SvREFCNT_dec(_pPin);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_Logout(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Logout) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    return module->function_list->C_Logout(hSession);
}

static CK_RV __check_pTemplate(AV* pTemplate, CK_ULONG_PTR pulCount, int allow_undef_pValue) {
    I32 key;
    SV** item;
    SV** type;
    SV** pValue;

    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pulCount) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Count the number of items in the template array and check that they are
     * valid hashes.
     */

    *pulCount = 0;
    for (key = 0; key < av_len(pTemplate); key++) {
        item = av_fetch(pTemplate, key, 0);

        if (!item || !*item) {
            continue;
        }

        if (SvTYPE(*item) != SVt_PVHV) {
            return CKR_ARGUMENTS_BAD;
        }

        type = hv_fetch((HV*)*item, __type_str, sizeof(__type_str)-1, 0);
        pValue = hv_fetch((HV*)*item, __pValue_str, sizeof(__pValue_str)-1, 0);

        if (!type
            || !*type
            || !SvIOK(*type)
            || (!allow_undef_pValue
                && (!pValue
                    || !*pValue
                    || !SvPOK(*pValue)))
            || (allow_undef_pValue
                && pValue
                && (!*pValue
                    || !SvPOK(*pValue))))
        {
            return CKR_ARGUMENTS_BAD;
        }

        *pulCount++;
    }

    return CKR_OK;
}

static CK_RV __create_CK_ATTRIBUTE(CK_ATTRIBUTE_PTR* ppTemplate, AV* pTemplate, CK_ULONG ulCount, int allow_undef_pValue) {
    I32 key;
    SV** item;
    SV** type;
    SV** pValue;
    STRLEN len;
    CK_ULONG i;
    CK_VOID_PTR _pValue;

    if (!ppTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!ulCount) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Create CK_ATTRIBUTE objects and extract the information from the hash.
     */

    if (!(*ppTemplate = calloc(ulCount, sizeof(CK_ATTRIBUTE)))) {
        return CKR_HOST_MEMORY;
    }

    for (i = 0, key = 0; key < av_len(pTemplate); key++) {
        item = av_fetch(pTemplate, key, 0);

        if (!item || !*item) {
            continue;
        }

        if (SvTYPE(*item) != SVt_PVHV) {
            free(*ppTemplate);
            *ppTemplate = NULL_PTR;
            return CKR_GENERAL_ERROR;
        }

        if (i >= ulCount) {
            free(*ppTemplate);
            *ppTemplate = NULL_PTR;
            return CKR_GENERAL_ERROR;
        }

        type = hv_fetch((HV*)*item, __type_str, sizeof(__type_str)-1, 0);
        pValue = hv_fetch((HV*)*item, __pValue_str, sizeof(__pValue_str)-1, 0);

        _pValue = NULL_PTR;

        if (!type
            || !*type
            || !SvIOK(*type)
            || (!allow_undef_pValue
                && (!pValue
                    || !*pValue
                    || !SvPOK(*pValue)
                    || !(_pValue = SvPVbyte(*pValue, len))
                    || len < 0))
            || (allow_undef_pValue
                && pValue
                && (!*pValue
                    || !SvPOK(*pValue)
                    || !(_pValue = SvPVbyte(*pValue, len))
                    || len < 0)))
        {
            free(*ppTemplate);
            *ppTemplate = NULL_PTR;
            return CKR_GENERAL_ERROR;
        }

        (*ppTemplate)[i].type = (CK_ATTRIBUTE_TYPE)SvUV(*type);
        if (_pValue) {
            /*
             * TODO: What if len is 0 ?
             */
            (*ppTemplate)[i].pValue = _pValue;
            (*ppTemplate)[i].ulValueLen = (CK_ULONG)len;
        }
        else {
            (*ppTemplate)[i].pValue = NULL_PTR;
            (*ppTemplate)[i].ulValueLen = 0;
        }
        i++;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_CreateObject(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, AV* pTemplate, SV* phObject) {
    CK_ATTRIBUTE_PTR _pTemplate = NULL_PTR;
    CK_ULONG ulCount = 0;
    CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_CreateObject) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!phObject) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Count the number of items in the template array and check that they are
     * valid hashes.
     */

    if ((rv = __check_pTemplate(pTemplate, &ulCount, 0)) != CKR_OK) {
        return rv;
    }

    if (ulCount) {
        /*
         * Create CK_ATTRIBUTE objects and extract the information from the hash.
         */

        if ((rv = __create_CK_ATTRIBUTE(&_pTemplate, pTemplate, ulCount, 0)) != CKR_OK) {
            return rv;
        }
    }

    /*
     * Call CreateObject
     */

    if ((rv = module->function_list->C_CreateObject(hSession, _pTemplate, ulCount, &hObject)) != CKR_OK) {
        free(_pTemplate);
        return rv;
    }
    free(_pTemplate);

    SvGETMAGIC(phObject);
    sv_setuv(phObject, hObject);
    SvSETMAGIC(phObject);

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_CopyObject(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, AV* pTemplate, SV* phNewObject) {
    CK_ATTRIBUTE_PTR _pTemplate = NULL_PTR;
    CK_ULONG ulCount = 0;
    CK_OBJECT_HANDLE hNewObject = CK_INVALID_HANDLE;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_CopyObject) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hObject == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!phNewObject) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Count the number of items in the template array and check that they are
     * valid hashes.
     */

    if ((rv = __check_pTemplate(pTemplate, &ulCount, 0)) != CKR_OK) {
        return rv;
    }

    if (ulCount) {
        /*
         * Create CK_ATTRIBUTE objects and extract the information from the hash.
         */

        if ((rv = __create_CK_ATTRIBUTE(&_pTemplate, pTemplate, ulCount, 0)) != CKR_OK) {
            return rv;
        }
    }

    /*
     * Call CopyObject
     */

    if ((rv = module->function_list->C_CopyObject(hSession, hObject, _pTemplate, ulCount, &hNewObject)) != CKR_OK) {
        free(_pTemplate);
        return rv;
    }
    free(_pTemplate);

    SvGETMAGIC(phNewObject);
    sv_setuv(phNewObject, hNewObject);
    SvSETMAGIC(phNewObject);

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_DestroyObject(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DestroyObject) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hObject == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    return module->function_list->C_DestroyObject(hSession, hObject);
}

CK_RV crypt_pkcs11_xs_C_GetObjectSize(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, SV* pulSize) {
    CK_ULONG ulSize = 0;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetObjectSize) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hObject == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pulSize) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = module->function_list->C_GetObjectSize(hSession, hObject, &ulSize)) == CKR_OK) {
        sv_setuv(pulSize, ulSize);
    }

    return rv;
}

CK_RV crypt_pkcs11_xs_C_GetAttributeValue(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, AV* pTemplate) {
    CK_ATTRIBUTE_PTR _pTemplate;
    CK_ULONG ulCount = 0;
    I32 key;
    SV** item;
    SV** type;
    SV** ulValueLen;
    CK_ULONG i;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_GetAttributeValue) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hObject == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Count the number of items in the template array and check that they are
     * valid hashes.
     */

    if ((rv = __check_pTemplate(pTemplate, &ulCount, 1)) != CKR_OK) {
        return rv;
    }

    if (ulCount) {
        /*
         * Create CK_ATTRIBUTE objects and extract the information from the hash.
         */

        if ((rv = __create_CK_ATTRIBUTE(&_pTemplate, pTemplate, ulCount, 1)) != CKR_OK) {
            return rv;
        }
    }

    /*
     * Call GetAttributeValue
     */

    if ((rv = module->function_list->C_GetAttributeValue(hSession, hObject, _pTemplate, ulCount)) != CKR_OK) {
        free(_pTemplate);
        return rv;
    }

    /*
     * Walk the array again, for all values insert a hash entry with the size
     * of the value for that type.
     */

    for (i = 0, key = 0; key < av_len(pTemplate); key++) {
        item = av_fetch(pTemplate, key, 0);

        if (!item || !*item) {
            continue;
        }

        if (SvTYPE(*item) != SVt_PVHV) {
            free(_pTemplate);
            return CKR_GENERAL_ERROR;
        }

        if (i >= ulCount) {
            free(_pTemplate);
            return CKR_GENERAL_ERROR;
        }

        type = hv_fetch((HV*)*item, __type_str, sizeof(__type_str)-1, 0);
        ulValueLen = hv_fetch((HV*)*item, __ulValueLen_str, sizeof(__ulValueLen_str)-1, 0);

        if (!type
            || !*type
            || !SvIOK(*type)
            || _pTemplate[i].type != SvUV(*type))
        {
            free(_pTemplate);
            return CKR_GENERAL_ERROR;
        }

        if (!ulValueLen || !*ulValueLen) {
            hv_store((HV*)*item, __ulValueLen_str, sizeof(__ulValueLen_str)-1, newSVuv(_pTemplate[i].ulValueLen), 0);
        }
        else {
            sv_setuv(*ulValueLen, _pTemplate[i].ulValueLen);
        }
        i++;
    }
    free(_pTemplate);

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_SetAttributeValue(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, AV* pTemplate) {
    CK_ATTRIBUTE_PTR _pTemplate = NULL_PTR;
    CK_ULONG ulCount = 0;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SetAttributeValue) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hObject == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Count the number of items in the template array and check that they are
     * valid hashes.
     */

    if ((rv = __check_pTemplate(pTemplate, &ulCount, 1)) != CKR_OK) {
        return rv;
    }

    if (ulCount) {
        /*
         * Create CK_ATTRIBUTE objects and extract the information from the hash.
         */

        if ((rv = __create_CK_ATTRIBUTE(&_pTemplate, pTemplate, ulCount, 1)) != CKR_OK) {
            return rv;
        }
    }

    /*
     * Call SetAttributeValue
     */

    rv = module->function_list->C_SetAttributeValue(hSession, hObject, _pTemplate, ulCount);
    free(_pTemplate);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_FindObjectsInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, AV* pTemplate) {
    CK_ATTRIBUTE_PTR _pTemplate = NULL_PTR;
    CK_ULONG ulCount = 0;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_FindObjectsInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTemplate) {
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * Count the number of items in the template array and check that they are
     * valid hashes.
     */

    if ((rv = __check_pTemplate(pTemplate, &ulCount, 1)) != CKR_OK) {
        return rv;
    }

    if (ulCount) {
        /*
         * Create CK_ATTRIBUTE objects and extract the information from the hash.
         */

        if ((rv = __create_CK_ATTRIBUTE(&_pTemplate, pTemplate, ulCount, 1)) != CKR_OK) {
            return rv;
        }
    }

    /*
     * Call FindObjectsInit
     */

    rv = module->function_list->C_FindObjectsInit(hSession, _pTemplate, ulCount);
    free(_pTemplate);

    return rv;
}

CK_RV crypt_pkcs11_xs_C_FindObjects(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, AV* phObject, CK_ULONG ulMaxObjectCount) {
    CK_OBJECT_HANDLE_PTR _phObject;
    CK_ULONG ulObjectCount;
    CK_ULONG i;
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_FindObjects) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!phObject) {
        return CKR_ARGUMENTS_BAD;
    }

    if (!ulMaxObjectCount) {
        return CKR_OK;
    }

    if (!(_phObject = calloc(ulMaxObjectCount, sizeof(CK_OBJECT_HANDLE)))) {
        return CKR_HOST_MEMORY;
    }

    if ((rv = module->function_list->C_FindObjects(hSession, _phObject, ulMaxObjectCount, &ulObjectCount)) != CKR_OK) {
        free(_phObject);
        return rv;
    }

    for (i = 0; i < ulObjectCount; i++) {
        av_push(phObject, newSVuv(_phObject[i]));
    }
    free(_phObject);

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_FindObjectsFinal(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_FindObjectsFinal) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    return module->function_list->C_FindObjectsFinal(hSession);
}

static CK_RV __action_init(HV* pMechanism, CK_MECHANISM_PTR _pMechanism) {
    SV** mechanism;
    SV** pParameter;
    char* _pParameter;
    STRLEN ulParameterLen;

    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!_pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }

    mechanism = hv_fetch(pMechanism, __mechanism_str, sizeof(__mechanism_str)-1, 0);
    pParameter = hv_fetch(pMechanism, __pParameter_str, sizeof(__pParameter_str)-1, 0);

    if (!mechanism
        || !*mechanism
        || !SvIOK(*mechanism)
        || (pParameter
            && (!*pParameter
                || !SvPOK(*pParameter)
                || !(_pParameter = SvPVbyte(*pParameter, ulParameterLen))
                || ulParameterLen < 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }

    _pMechanism->mechanism = SvUV(*mechanism);
    if (pParameter) {
        /*
         * TODO: What if ulParameterLen is 0 ?
         */
        _pMechanism->pParameter = _pParameter;
        _pMechanism->ulParameterLen = (CK_ULONG)ulParameterLen;
    }

    return CKR_OK;
}

typedef CK_RV (*__action_call_t)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);

static CK_RV __action(__action_call_t call, CK_SESSION_HANDLE hSession, SV* pFrom, SV* pTo) {
    char* _pFrom;
    STRLEN ulFromLen;
    char* _pTo;
    STRLEN ulToLen;
    CK_ULONG pulToLen;
    CK_RV rv;

    if (!call) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pFrom) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pTo) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pFrom);
    SvGETMAGIC(pTo);
    if (!(_pFrom = SvPVbyte(pFrom, ulFromLen))
        || ulFromLen < 0
        || !(_pTo = SvPVbyte(pTo, ulToLen))
        || ulToLen < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!ulToLen) {
        /*
         * If pTo is not pre-allocated when we ask the PKCS#11 module how much
         * memory it will need for the encryption.
         */

        if ((rv = call(hSession, _pFrom, (CK_ULONG)ulFromLen, NULL_PTR, &pulToLen)) != CKR_OK) {
            return rv;
        }
        if (!pulToLen) {
            return CKR_GENERAL_ERROR;
        }
        if (!(_pTo = calloc(pulToLen, sizeof(CK_BYTE)))) {
            return CKR_HOST_MEMORY;
        }
    }
    else {
        pulToLen = ulToLen;
    }

    if ((rv = call(hSession, _pFrom, (CK_ULONG)ulFromLen, _pTo, &pulToLen)) != CKR_OK) {
        if (!ulToLen) {
            free(_pTo);
        }
        return rv;
    }

    if (!ulToLen) {
        sv_setpvn(pTo, _pTo, pulToLen * sizeof(CK_BYTE));
        free(_pTo);
    }
    else if (pulToLen != ulToLen) {
        /*
         * Encrypted data length has changed so we create a new SV for it.
         */

        SV* pNewTo = newSVpvn(_pTo, pulToLen);

        if (!pNewTo) {
            return CKR_HOST_MEMORY;
        }

        sv_setsv(pTo, pNewTo);
        SvREFCNT_dec(pNewTo);
    }
    SvSETMAGIC(pTo);

    return CKR_OK;
}

typedef CK_RV (*__action_update_call_t)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

static CK_RV __action_update(__action_update_call_t call, CK_SESSION_HANDLE hSession, SV* pFrom) {
    char* _pFrom;
    STRLEN ulFromLen;

    if (!call) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pFrom) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pFrom);
    if (!(_pFrom = SvPVbyte(pFrom, ulFromLen))
        || ulFromLen < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return call(hSession, _pFrom, ulFromLen);
}

typedef CK_RV (*__action_final_call_t)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

static CK_RV __action_final(__action_final_call_t call, CK_SESSION_HANDLE hSession, SV* pLastPart) {
    char* _pLastPart;
    STRLEN ulLastPartLen;
    CK_ULONG pulLastPartLen;
    CK_RV rv;

    if (!call) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pLastPart) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pLastPart);
    if (!(_pLastPart = SvPVbyte(pLastPart, ulLastPartLen))
        || ulLastPartLen < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!ulLastPartLen) {
        /*
         * If pLastPart is not pre-allocated when we ask the PKCS#11 module how
         * much memory it will need for the encryption.
         */

        if ((rv = call(hSession, NULL_PTR, &pulLastPartLen)) != CKR_OK) {
            return rv;
        }
        if (!pulLastPartLen) {
            return CKR_GENERAL_ERROR;
        }
        if (!(_pLastPart = calloc(pulLastPartLen, sizeof(CK_BYTE)))) {
            return CKR_HOST_MEMORY;
        }
    }
    else {
        pulLastPartLen = ulLastPartLen;
    }

    if ((rv = call(hSession, _pLastPart, &pulLastPartLen)) != CKR_OK) {
        if (!ulLastPartLen) {
            free(_pLastPart);
        }
        return rv;
    }

    if (!ulLastPartLen) {
        sv_setpvn(pLastPart, _pLastPart, pulLastPartLen * sizeof(CK_BYTE));
        free(_pLastPart);
    }
    else if (pulLastPartLen != ulLastPartLen) {
        /*
         * Encrypted data length has changed so we create a new SV for it.
         */

        SV* pNewLastPart = newSVpvn(_pLastPart, pulLastPartLen);

        if (!pNewLastPart) {
            return CKR_HOST_MEMORY;
        }

        sv_setsv(pLastPart, pNewLastPart);
        SvREFCNT_dec(pNewLastPart);
    }
    SvSETMAGIC(pLastPart);

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_EncryptInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_EncryptInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_EncryptInit(hSession, &_pMechanism, hKey);
}

CK_RV crypt_pkcs11_xs_C_Encrypt(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pData, SV* pEncryptedData) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Encrypt) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedData) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_Encrypt, hSession, pData, pEncryptedData);
}

CK_RV crypt_pkcs11_xs_C_EncryptUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPart, SV* pEncryptedPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_EncryptUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_EncryptUpdate, hSession, pPart, pEncryptedPart);
}

CK_RV crypt_pkcs11_xs_C_EncryptFinal(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pLastEncryptedPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_EncryptFinal) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pLastEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_final(module->function_list->C_EncryptFinal, hSession, pLastEncryptedPart);
}

CK_RV crypt_pkcs11_xs_C_DecryptInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DecryptInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_DecryptInit(hSession, &_pMechanism, hKey);
}

CK_RV crypt_pkcs11_xs_C_Decrypt(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pEncryptedData, SV* pData) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Decrypt) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_Decrypt, hSession, pEncryptedData, pData);
}

CK_RV crypt_pkcs11_xs_C_DecryptUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pEncryptedPart, SV* pPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DecryptUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_DecryptUpdate, hSession, pEncryptedPart, pPart);
}

CK_RV crypt_pkcs11_xs_C_DecryptFinal(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pLastPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DecryptFinal) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pLastPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_final(module->function_list->C_DecryptFinal, hSession, pLastPart);
}

CK_RV crypt_pkcs11_xs_C_DigestInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DigestInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_DigestInit(hSession, &_pMechanism);
}

CK_RV crypt_pkcs11_xs_C_Digest(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pData, SV* pDigest) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Digest) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pDigest) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_Digest, hSession, pData, pDigest);
}

CK_RV crypt_pkcs11_xs_C_DigestUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DigestUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_update(module->function_list->C_DigestUpdate, hSession, pPart);
}

CK_RV crypt_pkcs11_xs_C_DigestKey(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_DigestFinal(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pDigest) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DigestFinal) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pDigest) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_final(module->function_list->C_DigestFinal, hSession, pDigest);
}

CK_RV crypt_pkcs11_xs_C_SignInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SignInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_SignInit(hSession, &_pMechanism, hKey);
}

CK_RV crypt_pkcs11_xs_C_Sign(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pData, SV* pSignature) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Sign) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSignature) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_Sign, hSession, pData, pSignature);
}

CK_RV crypt_pkcs11_xs_C_SignUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SignUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_update(module->function_list->C_SignUpdate, hSession, pPart);
}

CK_RV crypt_pkcs11_xs_C_SignFinal(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pSignature) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SignFinal) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSignature) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_final(module->function_list->C_SignFinal, hSession, pSignature);
}

CK_RV crypt_pkcs11_xs_C_SignRecoverInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SignRecoverInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_SignRecoverInit(hSession, &_pMechanism, hKey);
}

CK_RV crypt_pkcs11_xs_C_SignRecover(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pData, SV* pSignature) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SignRecover) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSignature) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_SignRecover, hSession, pData, pSignature);
}

CK_RV crypt_pkcs11_xs_C_VerifyInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_VerifyInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_VerifyInit(hSession, &_pMechanism, hKey);
}

CK_RV crypt_pkcs11_xs_C_Verify(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pData, SV* pSignature) {
    char* _pData;
    STRLEN ulDataLen;
    char* _pSignature;
    STRLEN ulSignatureLen;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_Verify) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSignature) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pData);
    SvGETMAGIC(pSignature);
    if (!(_pData = SvPVbyte(pData, ulDataLen))
        || ulDataLen < 0
        || !(_pSignature = SvPVbyte(pSignature, ulSignatureLen))
        || ulSignatureLen < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return module->function_list->C_Verify(hSession, _pData, (CK_ULONG)ulDataLen, _pSignature, (CK_ULONG)ulSignatureLen);
}

CK_RV crypt_pkcs11_xs_C_VerifyUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_VerifyUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action_update(module->function_list->C_VerifyUpdate, hSession, pPart);
}

CK_RV crypt_pkcs11_xs_C_VerifyFinal(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pSignature) {
    char* _pSignature;
    STRLEN ulSignatureLen;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_VerifyFinal) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSignature) {
        return CKR_ARGUMENTS_BAD;
    }

    SvGETMAGIC(pSignature);
    if (!(_pSignature = SvPVbyte(pSignature, ulSignatureLen))
        || ulSignatureLen < 0)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return module->function_list->C_VerifyFinal(hSession, _pSignature, ulSignatureLen);
}

CK_RV crypt_pkcs11_xs_C_VerifyRecoverInit(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hKey) {
    CK_MECHANISM _pMechanism = { 0, NULL_PTR, 0 };
    CK_RV rv;

    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_VerifyRecoverInit) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pMechanism) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = __action_init(pMechanism, &_pMechanism)) != CKR_OK) {
        return rv;
    }

    return module->function_list->C_VerifyRecoverInit(hSession, &_pMechanism, hKey);
}

CK_RV crypt_pkcs11_xs_C_VerifyRecover(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pData, SV* pSignature) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_VerifyRecover) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pData) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pSignature) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_VerifyRecover, hSession, pData, pSignature);
}

CK_RV crypt_pkcs11_xs_C_DigestEncryptUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPart, SV* pEncryptedPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DigestEncryptUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_DigestEncryptUpdate, hSession, pPart, pEncryptedPart);
}

CK_RV crypt_pkcs11_xs_C_DecryptDigestUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pEncryptedPart, SV* pPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DecryptDigestUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_DecryptDigestUpdate, hSession, pEncryptedPart, pPart);
}

CK_RV crypt_pkcs11_xs_C_SignEncryptUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pPart, SV* pEncryptedPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_SignEncryptUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_SignEncryptUpdate, hSession, pPart, pEncryptedPart);
}

CK_RV crypt_pkcs11_xs_C_DecryptVerifyUpdate(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pEncryptedPart, SV* pPart) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }
    if (!module->function_list->C_DecryptVerifyUpdate) {
        return CKR_GENERAL_ERROR;
    }
    if (hSession == CK_INVALID_HANDLE) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pEncryptedPart) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!pPart) {
        return CKR_ARGUMENTS_BAD;
    }

    return __action(module->function_list->C_DecryptVerifyUpdate, hSession, pEncryptedPart, pPart);
}

CK_RV crypt_pkcs11_xs_C_GenerateKey(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, AV* pTemplate, SV* phKey) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_GenerateKeyPair(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, AV* pPublicKeyTemplate, AV* pPrivateKeyTemplate, SV* phPublicKey, SV* phPrivateKey) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_WrapKey(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, SV* pWrappedKey) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_UnwrapKey(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, SV* pWrappedKey, AV* pTemplate, SV* phKey) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_DeriveKey(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, HV* pMechanism, CK_OBJECT_HANDLE hBaseKey, AV* pTemplate, SV* phKey) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_SeedRandom(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* pSeed) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_GenerateRandom(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession, SV* RandomData, CK_ULONG ulRandomLen) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_GetFunctionStatus(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_CancelFunction(Crypt__PKCS11__XS* module, CK_SESSION_HANDLE hSession) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV crypt_pkcs11_xs_C_WaitForSlotEvent(Crypt__PKCS11__XS* module, CK_FLAGS flags, SV* pSlot) {
    if (!module) {
        return CKR_ARGUMENTS_BAD;
    }
    if (!module->function_list) {
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}
