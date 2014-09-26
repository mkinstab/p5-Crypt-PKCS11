#!perl -T

use Test::More tests => 88;

use Crypt::PKCS11;

BEGIN {
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_OK), "CKR_OK" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_CANCEL), "CKR_CANCEL" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_HOST_MEMORY), "CKR_HOST_MEMORY" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SLOT_ID_INVALID), "CKR_SLOT_ID_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_GENERAL_ERROR), "CKR_GENERAL_ERROR" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_FUNCTION_FAILED), "CKR_FUNCTION_FAILED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ARGUMENTS_BAD), "CKR_ARGUMENTS_BAD" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_NO_EVENT), "CKR_NO_EVENT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_NEED_TO_CREATE_THREADS), "CKR_NEED_TO_CREATE_THREADS" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_CANT_LOCK), "CKR_CANT_LOCK" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ATTRIBUTE_READ_ONLY), "CKR_ATTRIBUTE_READ_ONLY" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ATTRIBUTE_SENSITIVE), "CKR_ATTRIBUTE_SENSITIVE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ATTRIBUTE_TYPE_INVALID), "CKR_ATTRIBUTE_TYPE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ATTRIBUTE_VALUE_INVALID), "CKR_ATTRIBUTE_VALUE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_DATA_INVALID), "CKR_DATA_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_DATA_LEN_RANGE), "CKR_DATA_LEN_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_DEVICE_ERROR), "CKR_DEVICE_ERROR" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_DEVICE_MEMORY), "CKR_DEVICE_MEMORY" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_DEVICE_REMOVED), "CKR_DEVICE_REMOVED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ENCRYPTED_DATA_INVALID), "CKR_ENCRYPTED_DATA_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_ENCRYPTED_DATA_LEN_RANGE), "CKR_ENCRYPTED_DATA_LEN_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_FUNCTION_CANCELED), "CKR_FUNCTION_CANCELED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_FUNCTION_NOT_PARALLEL), "CKR_FUNCTION_NOT_PARALLEL" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_FUNCTION_NOT_SUPPORTED), "CKR_FUNCTION_NOT_SUPPORTED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_HANDLE_INVALID), "CKR_KEY_HANDLE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_SIZE_RANGE), "CKR_KEY_SIZE_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_TYPE_INCONSISTENT), "CKR_KEY_TYPE_INCONSISTENT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_NOT_NEEDED), "CKR_KEY_NOT_NEEDED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_CHANGED), "CKR_KEY_CHANGED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_NEEDED), "CKR_KEY_NEEDED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_INDIGESTIBLE), "CKR_KEY_INDIGESTIBLE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_FUNCTION_NOT_PERMITTED), "CKR_KEY_FUNCTION_NOT_PERMITTED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_NOT_WRAPPABLE), "CKR_KEY_NOT_WRAPPABLE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_KEY_UNEXTRACTABLE), "CKR_KEY_UNEXTRACTABLE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_MECHANISM_INVALID), "CKR_MECHANISM_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_MECHANISM_PARAM_INVALID), "CKR_MECHANISM_PARAM_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_OBJECT_HANDLE_INVALID), "CKR_OBJECT_HANDLE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_OPERATION_ACTIVE), "CKR_OPERATION_ACTIVE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_OPERATION_NOT_INITIALIZED), "CKR_OPERATION_NOT_INITIALIZED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_PIN_INCORRECT), "CKR_PIN_INCORRECT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_PIN_INVALID), "CKR_PIN_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_PIN_LEN_RANGE), "CKR_PIN_LEN_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_PIN_EXPIRED), "CKR_PIN_EXPIRED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_PIN_LOCKED), "CKR_PIN_LOCKED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_CLOSED), "CKR_SESSION_CLOSED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_COUNT), "CKR_SESSION_COUNT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_HANDLE_INVALID), "CKR_SESSION_HANDLE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_PARALLEL_NOT_SUPPORTED), "CKR_SESSION_PARALLEL_NOT_SUPPORTED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_READ_ONLY), "CKR_SESSION_READ_ONLY" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_EXISTS), "CKR_SESSION_EXISTS" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_READ_ONLY_EXISTS), "CKR_SESSION_READ_ONLY_EXISTS" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SESSION_READ_WRITE_SO_EXISTS), "CKR_SESSION_READ_WRITE_SO_EXISTS" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SIGNATURE_INVALID), "CKR_SIGNATURE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SIGNATURE_LEN_RANGE), "CKR_SIGNATURE_LEN_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_TEMPLATE_INCOMPLETE), "CKR_TEMPLATE_INCOMPLETE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_TEMPLATE_INCONSISTENT), "CKR_TEMPLATE_INCONSISTENT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_TOKEN_NOT_PRESENT), "CKR_TOKEN_NOT_PRESENT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_TOKEN_NOT_RECOGNIZED), "CKR_TOKEN_NOT_RECOGNIZED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_TOKEN_WRITE_PROTECTED), "CKR_TOKEN_WRITE_PROTECTED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_UNWRAPPING_KEY_HANDLE_INVALID), "CKR_UNWRAPPING_KEY_HANDLE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_UNWRAPPING_KEY_SIZE_RANGE), "CKR_UNWRAPPING_KEY_SIZE_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT), "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_USER_ALREADY_LOGGED_IN), "CKR_USER_ALREADY_LOGGED_IN" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_USER_NOT_LOGGED_IN), "CKR_USER_NOT_LOGGED_IN" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_USER_PIN_NOT_INITIALIZED), "CKR_USER_PIN_NOT_INITIALIZED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_USER_TYPE_INVALID), "CKR_USER_TYPE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_USER_ANOTHER_ALREADY_LOGGED_IN), "CKR_USER_ANOTHER_ALREADY_LOGGED_IN" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_USER_TOO_MANY_TYPES), "CKR_USER_TOO_MANY_TYPES" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_WRAPPED_KEY_INVALID), "CKR_WRAPPED_KEY_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_WRAPPED_KEY_LEN_RANGE), "CKR_WRAPPED_KEY_LEN_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_WRAPPING_KEY_HANDLE_INVALID), "CKR_WRAPPING_KEY_HANDLE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_WRAPPING_KEY_SIZE_RANGE), "CKR_WRAPPING_KEY_SIZE_RANGE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_WRAPPING_KEY_TYPE_INCONSISTENT), "CKR_WRAPPING_KEY_TYPE_INCONSISTENT" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_RANDOM_SEED_NOT_SUPPORTED), "CKR_RANDOM_SEED_NOT_SUPPORTED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_RANDOM_NO_RNG), "CKR_RANDOM_NO_RNG" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_DOMAIN_PARAMS_INVALID), "CKR_DOMAIN_PARAMS_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_BUFFER_TOO_SMALL), "CKR_BUFFER_TOO_SMALL" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_SAVED_STATE_INVALID), "CKR_SAVED_STATE_INVALID" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_INFORMATION_SENSITIVE), "CKR_INFORMATION_SENSITIVE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_STATE_UNSAVEABLE), "CKR_STATE_UNSAVEABLE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_CRYPTOKI_NOT_INITIALIZED), "CKR_CRYPTOKI_NOT_INITIALIZED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_CRYPTOKI_ALREADY_INITIALIZED), "CKR_CRYPTOKI_ALREADY_INITIALIZED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_MUTEX_BAD), "CKR_MUTEX_BAD" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_MUTEX_NOT_LOCKED), "CKR_MUTEX_NOT_LOCKED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_NEW_PIN_MODE), "CKR_NEW_PIN_MODE" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_NEXT_OTP), "CKR_NEXT_OTP" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_FUNCTION_REJECTED), "CKR_FUNCTION_REJECTED" );
    is( Crypt::PKCS11::XS::rv2str(Crypt::PKCS11::CKR_VENDOR_DEFINED), "CKR_VENDOR_DEFINED" );
}