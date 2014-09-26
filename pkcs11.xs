#include "crypt_pkcs11.h"

/*
CK_RV
crypt_pkcs11_xs_C_GetFunctionList
    CK_FUNCTION_LIST_PTR_PTR ppFunctionList
*/

MODULE = Crypt::PKCS11::XS  PACKAGE = Crypt::PKCS11::XS  PREFIX = crypt_pkcs11_xs_

PROTOTYPES: ENABLE

Crypt::PKCS11::XS*
crypt_pkcs11_xs_new()
PROTOTYPE: DISABLE
OUTPUT:
    RETVAL

const char*
crypt_pkcs11_xs_rv2str(rv)
    CK_RV rv
PROTOTYPE: $
OUTPUT:
    RETVAL

void
crypt_pkcs11_xs_setCreateMutex(pCreateMutex)
    SV* pCreateMutex
PROTOTYPE: $

void
crypt_pkcs11_xs_clearCreateMutex()
PROTOTYPE: DISABLE

void
crypt_pkcs11_xs_setDestroyMutex(pDestroyMutex)
    SV* pDestroyMutex
PROTOTYPE: $

void
crypt_pkcs11_xs_clearDestroyMutex()
PROTOTYPE: DISABLE

void
crypt_pkcs11_xs_setLockMutex(pLockMutex)
    SV* pLockMutex
PROTOTYPE: $

void
crypt_pkcs11_xs_clearLockMutex()
PROTOTYPE: DISABLE

void
crypt_pkcs11_xs_setUnlockMutex(pUnlockMutex)
    SV* pUnlockMutex
PROTOTYPE: $

void
crypt_pkcs11_xs_clearUnlockMutex()
PROTOTYPE: DISABLE

MODULE = Crypt::PKCS11::XS  PACKAGE = Crypt::PKCS11::XSPtr  PREFIX = crypt_pkcs11_xs_

PROTOTYPES: ENABLE

CK_RV
crypt_pkcs11_xs_load(module, path)
    Crypt::PKCS11::XS* module
    const char* path
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_unload(module)
    Crypt::PKCS11::XS* module
PROTOTYPE: $
OUTPUT:
    RETVAL

void
crypt_pkcs11_xs_DESTROY(module)
    Crypt::PKCS11::XS* module
PROTOTYPE: $

CK_RV
crypt_pkcs11_xs_C_Initialize(module, pInitArgs)
    Crypt::PKCS11::XS* module
    HV* pInitArgs
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Finalize(module)
    Crypt::PKCS11::XS* module
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetInfo(module, pInfo)
    Crypt::PKCS11::XS* module
    HV* pInfo
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetSlotList(module, tokenPresent, pSlotList)
    Crypt::PKCS11::XS* module
    CK_BBOOL tokenPresent
    AV* pSlotList
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetSlotInfo(module, slotID, pInfo)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
    HV* pInfo
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetTokenInfo(module, slotID, pInfo)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
    HV* pInfo
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetMechanismList(module, slotID, pMechanismList)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
    AV* pMechanismList
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetMechanismInfo(module, slotID, type, pInfo)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
    CK_MECHANISM_TYPE type
    HV* pInfo
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_InitToken(module, slotID, pPin, pLabel)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
    SV* pPin
    SV* pLabel
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_InitPIN(module, hSession, pPin)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPin
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_SetPIN(module, hSession, pOldPin, pNewPin)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pOldPin
    SV* pNewPin
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_OpenSession(module, slotID, flags, Notify, phSession)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
    CK_FLAGS flags
    SV* Notify
    SV* phSession
PROTOTYPE: $$$$$
OUTPUT:
    RETVAL
    phSession

CK_RV
crypt_pkcs11_xs_C_CloseSession(module, hSession)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_CloseAllSessions(module, slotID)
    Crypt::PKCS11::XS* module
    CK_SLOT_ID slotID
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetSessionInfo(module, hSession, pInfo)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pInfo
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetOperationState(module, hSession, pOperationState)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pOperationState
PROTOTYPE: $$$
OUTPUT:
    RETVAL
    pOperationState

CK_RV
crypt_pkcs11_xs_C_SetOperationState(module, hSession, pOperationState, hEncryptionKey, hAuthenticationKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pOperationState
    CK_OBJECT_HANDLE hEncryptionKey
    CK_OBJECT_HANDLE hAuthenticationKey
PROTOTYPE: $$$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Login(module, hSession, userType, pPin)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_USER_TYPE userType
    SV* pPin
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Logout(module, hSession)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_CreateObject(module, hSession, pTemplate, phObject)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    AV* pTemplate
    SV* phObject
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    phObject

CK_RV
crypt_pkcs11_xs_C_CopyObject(module, hSession, hObject, pTemplate, phNewObject)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_OBJECT_HANDLE hObject
    AV* pTemplate
    SV* phNewObject
PROTOTYPE: $$$$$
OUTPUT:
    RETVAL
    phNewObject

CK_RV
crypt_pkcs11_xs_C_DestroyObject(module, hSession, hObject)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_OBJECT_HANDLE hObject
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GetObjectSize(module, hSession, hObject, pulSize)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_OBJECT_HANDLE hObject
    SV* pulSize
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pulSize

CK_RV
crypt_pkcs11_xs_C_GetAttributeValue(module, hSession, hObject, pTemplate)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_OBJECT_HANDLE hObject
    AV* pTemplate
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_SetAttributeValue(module, hSession, hObject, pTemplate)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_OBJECT_HANDLE hObject
    AV* pTemplate
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_FindObjectsInit(module, hSession, pTemplate)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    AV* pTemplate
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_FindObjects(module, hSession, phObject, ulMaxObjectCount)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    AV* phObject
    CK_ULONG ulMaxObjectCount
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    phObject

CK_RV
crypt_pkcs11_xs_C_FindObjectsFinal(module, hSession)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_EncryptInit(module, hSession, pMechanism, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Encrypt(module, hSession, pData, pEncryptedData)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pData
    SV* pEncryptedData
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pEncryptedData

CK_RV
crypt_pkcs11_xs_C_EncryptUpdate(module, hSession, pPart, pEncryptedPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPart
    SV* pEncryptedPart
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pEncryptedPart

CK_RV
crypt_pkcs11_xs_C_EncryptFinal(module, hSession, pLastEncryptedPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pLastEncryptedPart
PROTOTYPE: $$$
OUTPUT:
    RETVAL
    pLastEncryptedPart

CK_RV
crypt_pkcs11_xs_C_DecryptInit(module, hSession, pMechanism, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Decrypt(module, hSession, pEncryptedData, pData)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pEncryptedData
    SV* pData
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pData

CK_RV
crypt_pkcs11_xs_C_DecryptUpdate(module, hSession, pEncryptedPart, pPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pEncryptedPart
    SV* pPart
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pPart

CK_RV
crypt_pkcs11_xs_C_DecryptFinal(module, hSession, pLastPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pLastPart
PROTOTYPE: $$$
OUTPUT:
    RETVAL
    pLastPart

CK_RV
crypt_pkcs11_xs_C_DigestInit(module, hSession, pMechanism)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Digest(module, hSession, pData, pDigest)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pData
    SV* pDigest
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pDigest

CK_RV
crypt_pkcs11_xs_C_DigestUpdate(module, hSession, pPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPart
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_DigestKey(module, hSession, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_DigestFinal(module, hSession, pDigest)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pDigest
PROTOTYPE: $$$
OUTPUT:
    RETVAL
    pDigest

CK_RV
crypt_pkcs11_xs_C_SignInit(module, hSession, pMechanism, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Sign(module, hSession, pData, pSignature)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pData
    SV* pSignature
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pSignature

CK_RV
crypt_pkcs11_xs_C_SignUpdate(module, hSession, pPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPart
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_SignFinal(module, hSession, pSignature)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pSignature
PROTOTYPE: $$$
OUTPUT:
    RETVAL
    pSignature

CK_RV
crypt_pkcs11_xs_C_SignRecoverInit(module, hSession, pMechanism, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_SignRecover(module, hSession, pData, pSignature)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pData
    SV* pSignature
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pSignature

CK_RV
crypt_pkcs11_xs_C_VerifyInit(module, hSession, pMechanism, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_Verify(module, hSession, pData, pSignature)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pData
    SV* pSignature
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pSignature

CK_RV
crypt_pkcs11_xs_C_VerifyUpdate(module, hSession, pPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPart
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_VerifyFinal(module, hSession, pSignature)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pSignature
PROTOTYPE: $
OUTPUT:
    RETVAL
    pSignature

CK_RV
crypt_pkcs11_xs_C_VerifyRecoverInit(module, hSession, pMechanism, hKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hKey
PROTOTYPE: $$$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_VerifyRecover(module, hSession, pData, pSignature)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pData
    SV* pSignature
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pSignature

CK_RV
crypt_pkcs11_xs_C_DigestEncryptUpdate(module, hSession, pPart, pEncryptedPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPart
    SV* pEncryptedPart
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pEncryptedPart

CK_RV
crypt_pkcs11_xs_C_DecryptDigestUpdate(module, hSession, pEncryptedPart, pPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pEncryptedPart
    SV* pPart
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pPart

CK_RV
crypt_pkcs11_xs_C_SignEncryptUpdate(module, hSession, pPart, pEncryptedPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pPart
    SV* pEncryptedPart
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pEncryptedPart

CK_RV
crypt_pkcs11_xs_C_DecryptVerifyUpdate(module, hSession, pEncryptedPart, pPart)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pEncryptedPart
    SV* pPart
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    pPart

CK_RV
crypt_pkcs11_xs_C_GenerateKey(module, hSession, pMechanism, pTemplate, phKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    AV* pTemplate
    SV* phKey
PROTOTYPE: $$$$$
OUTPUT:
    RETVAL
    phKey

CK_RV
crypt_pkcs11_xs_C_GenerateKeyPair(module, hSession, pMechanism, pPublicKeyTemplate, pPrivateKeyTemplate, phPublicKey, phPrivateKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    AV* pPublicKeyTemplate
    AV* pPrivateKeyTemplate
    SV* phPublicKey
    SV* phPrivateKey
PROTOTYPE: $$$$$$$
OUTPUT:
    RETVAL
    phPublicKey
    phPrivateKey

CK_RV
crypt_pkcs11_xs_C_WrapKey(module, hSession, pMechanism, hWrappingKey, hKey, pWrappedKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hWrappingKey
    CK_OBJECT_HANDLE hKey
    SV* pWrappedKey
PROTOTYPE: $$$$$$
OUTPUT:
    RETVAL
    pWrappedKey

CK_RV
crypt_pkcs11_xs_C_UnwrapKey(module, hSession, pMechanism, hUnwrappingKey, pWrappedKey, pTemplate, phKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hUnwrappingKey
    SV* pWrappedKey
    AV* pTemplate
    SV* phKey
PROTOTYPE: $$$$$$$
OUTPUT:
    RETVAL
    phKey

CK_RV
crypt_pkcs11_xs_C_DeriveKey(module, hSession, pMechanism, hBaseKey, pTemplate, phKey)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    HV* pMechanism
    CK_OBJECT_HANDLE hBaseKey
    AV* pTemplate
    SV* phKey
PROTOTYPE: $$$$$$
OUTPUT:
    RETVAL
    phKey

CK_RV
crypt_pkcs11_xs_C_SeedRandom(module, hSession, pSeed)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* pSeed
PROTOTYPE: $$$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_GenerateRandom(module, hSession, RandomData, ulRandomLen)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
    SV* RandomData
    CK_ULONG ulRandomLen
PROTOTYPE: $$$$
OUTPUT:
    RETVAL
    RandomData

CK_RV
crypt_pkcs11_xs_C_GetFunctionStatus(module, hSession)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
PROTOTYPE: $$
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_CancelFunction(module, hSession)
    Crypt::PKCS11::XS* module
    CK_SESSION_HANDLE hSession
PROTOTYPE: $
OUTPUT:
    RETVAL

CK_RV
crypt_pkcs11_xs_C_WaitForSlotEvent(module, flags, pSlot)
    Crypt::PKCS11::XS* module
    CK_FLAGS flags
    SV* pSlot
PROTOTYPE: $
OUTPUT:
    RETVAL
    pSlot

MODULE = Crypt::PKCS11  PACKAGE = Crypt::PKCS11  PREFIX = crypt_pkcs11_

PROTOTYPES: ENABLE
