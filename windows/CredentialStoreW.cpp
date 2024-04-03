#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>

#include <strsafe.h>
#include <wincred.h>
#include <windows.h>

#include "CredentialStore.h"

void CSPrintSecErrorW(const wchar_t* Description, const long Status)
{
   PRECONDITION(Description != 0);

   wchar_t* MessageBuffer   = 0;
   size_t MessageBufferSize = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, Status, MAKELCID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (LPWSTR)&MessageBuffer, 0, 0);
   if (MessageBufferSize > 0) {
      std::wcout << Description << L", rc = " << Status << L", " << MessageBuffer << std::endl;
   }
   if (MessageBuffer != 0) {
      LocalFree(MessageBuffer);
      MessageBuffer = 0;
   }
   MessageBufferSize = 0;
}

int32_t CSCreateCredentialsW(
   const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(pPassword != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength <= CRED_MAX_CREDENTIAL_BLOB_SIZE, STATUS_INVALID_PARAMETER);

   int32_t Status           = STATUS_FAILURE;
   PCREDENTIALW pCredential = {0};
   if (CredReadW(ServiceName, CRED_TYPE_GENERIC, 0, &pCredential) == FALSE) {
      CREDENTIALW Credential        = {0};
      Credential.Type               = CRED_TYPE_GENERIC;
      Credential.TargetName         = (LPWSTR)ServiceName;
      Credential.Comment            = L"Created by StudioLink credential store";
      Credential.CredentialBlobSize = (DWORD)PasswordLength;
      Credential.CredentialBlob     = (LPBYTE)pPassword;
      Credential.Persist            = CRED_PERSIST_LOCAL_MACHINE;
      Credential.UserName           = (LPWSTR)LoginName;

      if (CredWriteW(&Credential, 0) != FALSE) {
         Status = STATUS_SUCCESS;
      }
      else {
         CSPrintSecErrorW(L"CredWrite failed", GetLastError());
         Status = STATUS_FAILURE;
      }
   }
   else {
      CredFree(pCredential);
      pCredential = 0;
      CSPrintSecErrorW(L"CredWrite failed", ERROR_ALREADY_EXISTS);
      Status = STATUS_ITEM_ALREADY_EXISTS;
   }
   return Status;
}

int32_t CSReadCredentialsW(
   const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength, void** ppPassword,
   size_t* pPasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ppPassword != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(pPasswordLength != NULL, STATUS_INVALID_PARAMETER);

   int32_t Status           = STATUS_FAILURE;
   *ppPassword              = 0;
   *pPasswordLength         = 0;
   PCREDENTIALW pCredential = {0};
   if (CredReadW(ServiceName, CRED_TYPE_GENERIC, 0, &pCredential) != FALSE) {
      Status = CSAllocPassword(ppPassword, pCredential->CredentialBlobSize);
      if (STATUS_SUCCESS == Status) {
         memmove(*ppPassword, pCredential->CredentialBlob, pCredential->CredentialBlobSize);
         *pPasswordLength = pCredential->CredentialBlobSize;
         Status           = STATUS_SUCCESS;
      }
      CredFree(pCredential);
      pCredential = 0;
      Status      = STATUS_SUCCESS;
   }
   else {
      const long Status = GetLastError();
      CSPrintSecErrorW(L"CredRead failed", Status);

      if (ERROR_NOT_FOUND == Status) {
         Status = STATUS_ITEM_NOT_FOUND;
      }
      else {
         Status = STATUS_FAILURE;
      }
   }
   return Status;
}

int32_t CSUpdateCredentialsW(
   const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength, const void* pPassword,
   const size_t PasswordLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(pPassword != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(PasswordLength <= CRED_MAX_CREDENTIAL_BLOB_SIZE, STATUS_INVALID_PARAMETER);

   int32_t Status           = STATUS_FAILURE;
   PCREDENTIALW pCredential = {0};
   if (CredReadW(ServiceName, CRED_TYPE_GENERIC, 0, &pCredential) != FALSE) {
      CredFree(pCredential);
      pCredential                   = 0;
      CREDENTIALW Credential        = {0};
      Credential.Type               = CRED_TYPE_GENERIC;
      Credential.TargetName         = (LPWSTR)ServiceName;
      Credential.Comment            = L"Created by StudioLink credential store";
      Credential.CredentialBlobSize = (DWORD)PasswordLength;
      Credential.CredentialBlob     = (LPBYTE)pPassword;
      Credential.Persist            = CRED_PERSIST_LOCAL_MACHINE;
      Credential.UserName           = (LPWSTR)LoginName;

      if (CredWriteW(&Credential, 0) != FALSE) {
         Status = STATUS_SUCCESS;
      }
      else {
         CSPrintSecErrorW(L"CredWrite failed", GetLastError());
         Status = STATUS_FAILURE;
      }
   }
   else {
      CSPrintSecErrorW(L"CredWrite failed", ERROR_NOT_FOUND);
      Status = STATUS_ITEM_NOT_FOUND;
   }
   return Status;
}

int32_t CSDeleteCredentialsW(const wchar_t* ServiceName, const size_t ServiceNameLength, const wchar_t* LoginName, const size_t LoginNameLength)
{
   PRECONDITION_RETURN(ServiceName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(ServiceNameLength > 0, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginName != NULL, STATUS_INVALID_PARAMETER);
   PRECONDITION_RETURN(LoginNameLength > 0, STATUS_INVALID_PARAMETER);

   int32_t Status = STATUS_FAILURE;
   if (CredDeleteW(ServiceName, CRED_TYPE_GENERIC, 0) != FALSE) {
      Status = STATUS_SUCCESS;
   }
   else {
      const long Status = GetLastError();
      CSPrintSecErrorW(L"CredDelete failed", Status);

      if (ERROR_NOT_FOUND == Status) {
         Status = STATUS_ITEM_NOT_FOUND;
      }
      else {
         Status = STATUS_FAILURE;
      }
   }
   return Status;
}
