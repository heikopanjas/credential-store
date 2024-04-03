#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>

#include "CredentialStore.h"

NcsStatus NcsPrintSecError(const char* Description, const OSStatus systemStatus)
{
   NCS_PRECONDITION_RETURN(Description != 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status         = NCS_STATUS_FAILURE;
   CFStringRef ErrorMessage = SecCopyErrorMessageString(systemStatus, 0);
   if (ErrorMessage != 0) {
      CFIndex MinBufferLength = CFStringGetLength(ErrorMessage);
      CFIndex MaxBufferLength = CFStringGetMaximumSizeForEncoding(MinBufferLength, kCFStringEncodingUTF8) + 1;
      char* Buffer            = (char*)calloc(MaxBufferLength, sizeof(char));
      if (Buffer != 0) {
         if (CFStringGetCString(ErrorMessage, Buffer, MaxBufferLength, kCFStringEncodingUTF8) != FALSE) {
            std::cout << Description << ", rc = " << (int32_t)systemStatus << ", '" << Buffer << "'" << std::endl;
            Status = NCS_STATUS_SUCCESS;
         }
         else {
            Status = NCS_STATUS_ITEM_NOT_FOUND;
         }
         free(Buffer);
         Buffer = 0;
      }
      else {
         Status = NCS_STATUS_OUT_OF_MEMORY;
      }

      CFRelease(ErrorMessage);
      ErrorMessage = 0;
   }
   else {
      Status = NCS_STATUS_ITEM_NOT_FOUND;
   }

   return Status;
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

   NcsStatus Status = NCS_STATUS_FAILURE;
   OSStatus Status =
      SecKeychainAddGenericPassword(0, (UInt32)ServiceNameLength, ServiceName, (UInt32)LoginNameLength, LoginName, (UInt32)PasswordLength, Password, 0);
   if (errSecSuccess == Status) {
      Status = NCS_STATUS_SUCCESS;
   }
   else {
      NcsPrintSecError("SecKeychainAddGenericPassword() failed", Status);
      if (errSecDuplicateItem == Status) {
         Status = NCS_STATUS_ITEM_ALREADY_EXISTS;
      }
      else {
         Status = NCS_STATUS_FAILURE;
      }
   }

   return Status;
}

NcsStatus NcsReadCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, void** pPassword, size_t* pPasswordLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(pPassword != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(pPasswordLength != 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status        = NCS_STATUS_FAILURE;
   *pPasswordLength        = 0;
   *pPassword              = 0;
   void* PasswordBuffer    = 0;
   SecKeychainItemRef Item = 0;
   OSStatus Status         = SecKeychainFindGenericPassword(
              0, (UInt32)ServiceNameLength, ServiceName, (UInt32)LoginNameLength, LoginName, (UInt32*)pPasswordLength, &PasswordBuffer, &Item);
   if (errSecSuccess == Status) {
      Status = CSAllocPassword(pPassword, *pPasswordLength);
      if ((NCS_STATUS_SUCCESS == Status) && (*pPassword != 0)) {
         memmove(*pPassword, PasswordBuffer, *pPasswordLength);
         Status = NCS_STATUS_SUCCESS;
      }

      SecKeychainItemFreeContent(0, PasswordBuffer);
      PasswordBuffer = 0;

      CFRelease(Item);
      Item = 0;
   }
   else {
      NcsPrintSecError("SecKeychainFindGenericPassword() failed", Status);

      if (errSecItemNotFound == Status) {
         Status = NCS_STATUS_ITEM_NOT_FOUND;
      }
      else {
         Status = NCS_STATUS_FAILURE;
      }
   }

   return Status;
}

NcsStatus NcsUpdateCredentials(
   const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength, const void* Password,
   const size_t PasswordLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(Password != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(PasswordLength > 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status        = NCS_STATUS_FAILURE;
   SecKeychainItemRef Item = 0;
   OSStatus Status         = SecKeychainFindGenericPassword(0, (UInt32)ServiceNameLength, ServiceName, (UInt32)LoginNameLength, LoginName, 0, 0, &Item);
   if (errSecSuccess == Status) {
      Status = SecKeychainItemModifyAttributesAndData(Item, 0, (UInt32)PasswordLength, Password);
      if (errSecSuccess == Status) {
         Status = NCS_STATUS_SUCCESS;
      }
      else {
         NcsPrintSecError("SecKeychainItemModifyAttributesAndData() failed", Status);
      }
   }
   else {
      NcsPrintSecError("SecKeychainFindGenericPassword() failed", Status);

      if (errSecItemNotFound == Status) {
         Status = NCS_STATUS_ITEM_NOT_FOUND;
      }
      else {
         Status = NCS_STATUS_FAILURE;
      }
   }

   return Status;
}

NcsStatus NcsDeleteCredentials(const char* ServiceName, const size_t ServiceNameLength, const char* LoginName, const size_t LoginNameLength)
{
   NCS_PRECONDITION_RETURN(ServiceName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(ServiceNameLength > 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginName != 0, NCS_STATUS_INVALID_PARAMETER);
   NCS_PRECONDITION_RETURN(LoginNameLength > 0, NCS_STATUS_INVALID_PARAMETER);

   NcsStatus Status        = NCS_STATUS_FAILURE;
   SecKeychainItemRef Item = 0;
   OSStatus Status         = SecKeychainFindGenericPassword(0, (UInt32)ServiceNameLength, ServiceName, (UInt32)LoginNameLength, LoginName, 0, 0, &Item);
   if (errSecSuccess == Status) {
      Status = SecKeychainItemDelete(Item);
      if (errSecSuccess == Status) {
         Status = NCS_STATUS_SUCCESS;
      }
      else {
         NcsPrintSecError("SecKeychainItemModifyAttributesAndData() failed", Status);
      }
   }
   else {
      NcsPrintSecError("SecKeychainFindGenericPassword() failed", Status);

      if (errSecItemNotFound == Status) {
         Status = NCS_STATUS_ITEM_NOT_FOUND;
      }
      else {
         Status = NCS_STATUS_FAILURE;
      }
   }

   return Status;
}

NcsStatus NcsAllocPassword(void** pPassword, const size_t PasswordLength)
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

void NcsReleasePassword(void** pPassword, const size_t PasswordLength)
{
   NCS_PRECONDITION(pPassword != 0);
   NCS_PRECONDITION(*pPassword != 0);
   NCS_PRECONDITION(PasswordLength > 0);

   memset(*pPassword, 0, PasswordLength);
   free(*pPassword);
   *pPassword = 0;
}
