#ifndef __ULTRALOVE_CREDENTIAL_STORE_H_INCL__
#define __ULTRALOVE_CREDENTIAL_STORE_H_INCL__

#include <stdint.h>

#define PRECONDITION(a) \
   if (!(a)) {          \
      return;           \
   }
#define PRECONDITION_RETURN(a, b) \
   if (!(a)) {                    \
      return (b);                 \
   }

#define SAFE_DELETE(a) \
   if ((a)) {          \
      free((a));       \
      a = NULL;        \
   }

#define NCS_STATUS_SUCCESS             0
#define NCS_STATUS_FAILURE             0x80000000
#define NCS_STATUS_INVALID_PARAMETER   0x80000001
#define NCS_STATUS_ITEM_NOT_FOUND      0x80000002
#define NCS_STATUS_ITEM_ALREADY_EXISTS 0x80000003
#define NCS_STATUS_OUT_OF_MEMORY       0x80000004

#ifndef __cplusplus__
extern "C" {
#endif // #ifndef __cplusplus__

int32_t CSCreateCredentialsW(
   const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength);

int32_t CSCreateCredentialsA(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength);

int32_t CSReadCredentialsW(
   const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength, void** ppPassword,
   size_t* pPasswordLength);

int32_t CSReadCredentialsA(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, void** ppPassword, size_t* pPasswordLength);

int32_t CSUpdateCredentialsW(
   const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength);

int32_t CSUpdateCredentialsA(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength);

int32_t CSDeleteCredentialsW(const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength);

int32_t CSDeleteCredentialsA(const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength);

#ifdef _WIN32
   #ifdef UNICODE
      #define CSCreateCredentials CSCreateCredentialsW
      #define CSReadCredentials   CSReadCredentialsW
      #define CSUpdateCredentials CSUpdateCredentialsW
      #define CSDeleteCredentials CSDeleteCredentialsW
   #else
      #define CSCreateCredentials CSCreateCredentialsA
      #define CSReadCredentials   CSReadCredentialsA
      #define CSUpdateCredentials CSUpdateCredentialsA
      #define CSDeleteCredentials CSDeleteCredentialsA
   #endif // #ifdef UNICODE
#endif    // #ifdef _WIN32

int32_t CSAllocPassword(void** ppPassword, const size_t PasswordLength);

void CSReleasePassword(void** ppPassword, const size_t PasswordLength);

#ifndef __cplusplus__
}
#endif // #ifndef __cplusplus__

#endif // #ifndef __ULTRALOVE_CREDENTIAL_STORE_H_INCL__
