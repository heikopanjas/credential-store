#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "CredentialStore.h"

NcsStatus CSPrintSecError(const char* Description, const NcsStatus Status)
{
   NCS_PRECONDITION_RETURN(Description != 0, NCS_STATUS_INVALID_PARAMETER);

   return NCS_STATUS_NOT_IMPLEMENTED_YET;
}

NcsStatus NcsCreateCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* Password,
   const size_t PasswordLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(Password != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(PasswordLength > 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status = NCS_STATUS_NOT_IMPLEMENTED_YET;
   return Status;
}

NcsStatus CSReadCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, void** pPassword, size_t* pPasswordLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(pPassword != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(pPasswordLength != 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status = NCS_STATUS_NOT_IMPLEMENTED_YET;
   return Status;
}

NcsStatus CSUpdateCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* Password,
   const size_t PasswordLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(Password != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(PasswordLength > 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status = NCS_STATUS_NOT_IMPLEMENTED_YET;
   return Status;
}

NcsStatus CSDeleteCredentials(const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status = NCS_STATUS_NOT_IMPLEMENTED_YET;
   return Status;
}

NcsStatus CSAllocPassword(void** pPassword, const size_t PasswordLength)
{
   NCS_PRECONDITION_RETURN(pPassword != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(*pPassword == 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(PasswordLength > 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status = NCS_STATUS_FAILURE;
   *pPassword       = calloc(PasswordLength, sizeof(char));
   if (*pPassword != 0) {
      Status = NCS_STATUS_SUCCESS;
   }
   else {
      Status = NCS_STATUS_OUT_OF_MEMORY;
   }
   return Status;
}

void CSReleasePassword(void** pPassword, const size_t PasswordLength)
{
   NCS_PRECONDITION(pPassword != 0);
   NCS_PRECONDITION(*pPassword != 0);
   NCS_PRECONDITION(PasswordLength > 0);

   memset(*pPassword, 0, PasswordLength);
   free(*pPassword);
   *pPassword = 0;
}
