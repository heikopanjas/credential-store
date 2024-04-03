#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>

#include <strsafe.h>
#include <wincred.h>
#include <windows.h>

#include "CredentialStore.h"

extern void CSPrintSecErrorW(const wchar_t* Description, const long Status);

void CSFreeUnicodeString(wchar_t** ppUnicodeString, const size_t UnicodeStringLength)
{
   PRECONDITION(ppUnicodeString != 0);
   PRECONDITION(*ppUnicodeString != 0);
   PRECONDITION(UnicodeStringLength > 0);

   memset((void*)*ppUnicodeString, 0, UnicodeStringLength);
   free((void*)*ppUnicodeString);
   *ppUnicodeString = 0;
}

int32_t CSAnsiStringToUnicodeString(const char* AnsiString, const size_t AnsiStringLength, wchar_t** ppUnicodeString, size_t* pUnicodeStringLength)
{
   PRECONDITION_RETURN(AnsiString != 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(AnsiStringLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ppUnicodeString != 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(pUnicodeStringLength != 0, STATUS_INVALID_PARAMETER);

   int32_t Status          = STATUS_FAILURE;
   int UnicodeStringLength = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, AnsiString, (int)AnsiStringLength, 0, 0);
   if (UnicodeStringLength > 0) {
      wchar_t* pUnicodeString = (wchar_t*)calloc(UnicodeStringLength + 1, sizeof(WCHAR));
      if (pUnicodeString != 0) {
         int ConvertedChars = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, AnsiString, (int)AnsiStringLength, pUnicodeString, UnicodeStringLength);
         if (ConvertedChars > 0) {
            *ppUnicodeString      = pUnicodeString;
            *pUnicodeStringLength = UnicodeStringLength;
            Status                = STATUS_SUCCESS;
         }
         else {
            CSFreeUnicodeString(&pUnicodeString, UnicodeStringLength);
            Status = STATUS_FAILURE;
         }
      }
      else {
         Status = STATUS_OUT_OF_MEMORY;
      }
   }
   return Status;
}

void CSPrintSecErrorA(const char* Description, const long Status)
{
   PRECONDITION(Description != 0);

   const size_t DescriptionLength = strlen(Description);
   if (DescriptionLength > 0) {
      LPWSTR UnicodeString       = 0;
      size_t UnicodeStringLength = 0;
      int32_t Status             = CSAnsiStringToUnicodeString(Description, DescriptionLength, &UnicodeString, &UnicodeStringLength);
      if (STATUS_SUCCESS == Status) {
         CSPrintSecErrorW(UnicodeString, Status);
         CSFreeUnicodeString(&UnicodeString, UnicodeStringLength);
      }
   }
}

int32_t CSCreateCredentialsA(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);

   wchar_t* ServiceNameBuffer     = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t Status                 = CSAnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if (STATUS_SUCCESS == Status) {
      wchar_t* LoginNameBuffer     = 0;
      size_t LoginNameBufferLength = 0;
      Status                       = CSAnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
      if (STATUS_SUCCESS == Status) {
         Status = CSCreateCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength, pPassword, PasswordLength);
         CSFreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
      }
      CSFreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }
   return Status;
}

int32_t CSReadCredentialsA(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, void** ppPassword, size_t* pPasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);

   wchar_t* ServiceNameBuffer     = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t Status                 = CSAnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if (STATUS_SUCCESS == Status) {
      wchar_t* LoginNameBuffer     = 0;
      size_t LoginNameBufferLength = 0;
      Status                       = CSAnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
      if (STATUS_SUCCESS == Status) {
         Status = CSReadCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength, ppPassword, pPasswordLength);
         CSFreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
      }
      CSFreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }
   return Status;
}

int32_t CSUpdateCredentialsA(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);

   wchar_t* ServiceNameBuffer     = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t Status                 = CSAnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if (STATUS_SUCCESS == Status) {
      wchar_t* LoginNameBuffer     = 0;
      size_t LoginNameBufferLength = 0;
      Status                       = CSAnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
      if (STATUS_SUCCESS == Status) {
         Status = CSUpdateCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength, pPassword, PasswordLength);
         CSFreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
      }
      CSFreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }
   return Status;
}

int32_t CSDeleteCredentialsA(const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);

   wchar_t* ServiceNameBuffer     = 0;
   size_t ServiceNameBufferLength = 0;
   int32_t Status                 = CSAnsiStringToUnicodeString(ServiceName, ServiceNameLength, &ServiceNameBuffer, &ServiceNameBufferLength);
   if (STATUS_SUCCESS == Status) {
      wchar_t* LoginNameBuffer     = 0;
      size_t LoginNameBufferLength = 0;
      Status                       = CSAnsiStringToUnicodeString(LoginName, LoginNameLength, &LoginNameBuffer, &LoginNameBufferLength);
      if (STATUS_SUCCESS == Status) {
         Status = CSDeleteCredentialsW(ServiceNameBuffer, ServiceNameBufferLength, LoginNameBuffer, LoginNameBufferLength);
         CSFreeUnicodeString(&LoginNameBuffer, LoginNameBufferLength);
      }
      CSFreeUnicodeString(&ServiceNameBuffer, ServiceNameBufferLength);
   }
   return Status;
}
