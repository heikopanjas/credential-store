#ifndef __ULTRALOVE_CREDENTIAL_STORE_H_INCL__
#define __ULTRALOVE_CREDENTIAL_STORE_H_INCL__

#include <stdint.h>

#define NCS_PRECONDITION(a) \
   if (!(a)) {              \
      return;               \
   }
#define NCS_PRECONDITION_RETURN(a, b) \
   if (!(a)) {                        \
      return (b);                     \
   }

#define NCS_SAFE_DELETE(a) \
   if ((a)) {              \
      free((a));           \
      a = 0;               \
   }

typedef int32_t NcsStatus;
static const NcsStatus NCS_STATUS_SUCCESS             = 0;
static const NcsStatus NCS_STATUS_FAILURE             = 0x80000000;
static const NcsStatus NCS_STATUS_INVALID_PARAMETER   = 0x80000001;
static const NcsStatus NCS_STATUS_ITEM_NOT_FOUND      = 0x80000002;
static const NcsStatus NCS_STATUS_ITEM_ALREADY_EXISTS = 0x80000003;
static const NcsStatus NCS_STATUS_OUT_OF_MEMORY       = 0x80000004;
static const NcsStatus NCS_STATUS_NOT_IMPLEMENTED_YET = 0x80000005;

#ifndef __cplusplus__
extern "C" {
#endif // #ifndef __cplusplus__

NcsStatus NcsCreateCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* Password,
   const size_t PasswordLength);

NcsStatus NcsReadCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, void** pPassword, size_t* pPasswordLength);

NcsStatus NcsUpdateCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* Password,
   const size_t PasswordLength);

NcsStatus NcsDeleteCredentials(const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength);

NcsStatus NcsAllocPassword(void** pPassword, const size_t PasswordLength);

void NcsReleasePassword(void** pPassword, const size_t PasswordLength);

#ifndef __cplusplus__
}
#endif // #ifndef __cplusplus__

#endif // #ifndef __ULTRALOVE_CREDENTIAL_STORE_H_INCL__
