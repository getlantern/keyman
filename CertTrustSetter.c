/*
*  CertTrustSetter.cpp
*  CertTrustTester
*
*  Created by Don Swatman on 24-Feb-2010.
*  Copyright 2010 Citrix Systems, Inc. All Rights Reserved.
*
*  This sample code is provided to you “AS IS” with no representations,
*  warranties or conditions of any kind.
*
*  You may use, modify and distribute it at your own risk.
*  CITRIX DISCLAIMS ALL WARRANTIES WHATSOEVER, EXPRESS, IMPLIED, WRITTEN,
*  ORAL OR STATUTORY,  INCLUDING WITHOUT LIMITATION WARRANTIES OF
*  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
*  NONINFRINGEMENT.
*
*  Without limiting the generality of the foregoing, you acknowledge and
*  agree that
* (a) the sample code may exhibit errors, design flaws or other problems,
*     possibly resulting in loss of data or damage to property;
* (b) it may not be possible to make the sample code fully functional;
*  and
* (c) Citrix may, without notice or liability to you, cease to make
*     available the current version and/or any future versions of the
*     sample code.
*
*  In no event should the code be used to support of ultra-hazardous
*  activities, including but not limited to life support or blasting
*  activities.
*  NEITHER CITRIX NOR ITS AFFILIATES OR AGENTS WILL BE LIABLE, UNDER
*  BREACH OF CONTRACT OR ANY OTHER THEORY OF LIABILITY, FOR ANY DAMAGES
*  WHATSOEVER ARISING FROM USE OF THE SAMPLE CODE, INCLUDING WITHOUT
*  LIMITATION DIRECT, SPECIAL, INCIDENTAL, PUNITIVE, CONSEQUENTIAL OR
*  OTHER DAMAGES, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
*
*  Although the copyright in the code belongs to Citrix, any distribution
*  of the code should include only your own standard copyright attribution,
*  and not that of Citrix.
*  You agree to indemnify and defend Citrix against any and all claims
*  arising from your use, modification or distribution of the code.
*/

#include "CertTrustSetter.h"

// --------------------------------------------------------
// Prototypes
// --------------------------------------------------------

CSSM_BOOL compareOids( const CSSM_OID *oid1, const CSSM_OID *oid2);


// --------------------------------------------------------
// addCertificateWithURL:
// --------------------------------------------------------
    
OSStatus addCertificateWithBytes(const uint8* bytes, int length, SecCertificateRef* returnCertRef)
{
    OSStatus result = noErr;

    CFDataRef data = CFDataCreate(NULL, bytes, length);
    if (data == NULL) {
        return -1;
    }

    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, data);
    if (certRef == NULL) {
        return -2;
    }
    returnCertRef = &certRef;
    
    // Add the certificate
    if (result == noErr)
    {
        result = SecCertificateAddToKeychain( certRef, NULL );

        // Duplication is not an error!
        if (result == errSecDuplicateItem)
            result = noErr;
    }
    
    // Clean up
    if (result != noErr)
        *returnCertRef = nil;
    
    return result;
}

// --------------------------------------------------------
// trustCertificate
// --------------------------------------------------------
// This non-destructively sets a policy on a certificate.
// Other policies will be left alone.

OSStatus trustCertificate( const SecCertificateRef  certificateRef,
                                 TrustPolicyAction* policyActionsHead )
{
    OSStatus            result                = noErr;
    CFArrayRef          trustSettingArray     = NULL;
    CFMutableArrayRef   trustSettingMutArray  = NULL;
    TrustPolicyAction*  onePolicyAction       = NULL;
    bool                trustSettingsDirty    = false;
    
    // Set handled to false
    onePolicyAction = policyActionsHead;
    while (onePolicyAction)
    {
        onePolicyAction->handled = false;
        onePolicyAction = onePolicyAction->nextAction;
    }
    
    // Get a copy of the trust settings array
    result = SecTrustSettingsCopyTrustSettings( certificateRef,
                                                kSecTrustSettingsDomainUser,
                                                &trustSettingArray );
    
    // Make or create a mutable copy
    if (result == noErr)
    {
        trustSettingMutArray = CFArrayCreateMutableCopy (NULL, 0, trustSettingArray );
    }
    else if (result == errSecItemNotFound)
    {
        result = noErr;
        trustSettingMutArray = CFArrayCreateMutable (NULL, 0, &kCFTypeArrayCallBacks);
    }
    
    // Scan the trust settings looking for the  policy.
    // If it's found check it's status and set it.
    CFIndex trustCounter;
    for (trustCounter = 0;
           (result == noErr) && (trustCounter < CFArrayGetCount(trustSettingMutArray));
           trustCounter++)
    {
   // Get one trust setting dictionary, make a mutable copy, then swap it for the mutable one
        CFDictionaryRef oneTrustSetting = (CFDictionaryRef)CFArrayGetValueAtIndex (
                                                                        trustSettingMutArray,
                                                                        trustCounter );
        CFMutableDictionaryRef oneMutTrustSetting = CFDictionaryCreateMutableCopy (
                                                                        NULL,
                                                                        0,
                                                                        oneTrustSetting );
        
        if (oneMutTrustSetting)
        {
            // Change the immutable array to the mutable one
            CFArraySetValueAtIndex ( trustSettingMutArray, trustCounter, oneMutTrustSetting );

            // Look to see if it has a policy
            SecPolicyRef policyRef;
            if (CFDictionaryGetValueIfPresent ( oneMutTrustSetting,
                                                  kSecTrustSettingsPolicy,
                                                (const void**)&policyRef ))
            {
                // Get the policy's OID
                CSSM_OID oid;
                if (SecPolicyGetOID (policyRef, &oid) == noErr)
                {
                    // see if policy is in the list of policies actions
                    onePolicyAction = policyActionsHead;
                    while (onePolicyAction)
                    {
                        if (compareOids( &oid, onePolicyAction->policy) == CSSM_TRUE)
                            break;
                        onePolicyAction = onePolicyAction->nextAction;
                    }
                    
                    // Policy is one we're interested in!
                    if (onePolicyAction)
                    {
                        if (onePolicyAction->action == kRemove)
                        {
                            CFArrayRemoveValueAtIndex( trustSettingMutArray, trustCounter );
                            trustCounter--;
                            // Mark the certificate as needing saving back to the keychain
                            onePolicyAction->handled = true;
                            trustSettingsDirty = true;
                        }
                        else
                        {
                            // Extract the trust value
                            CFNumberRef numberRef;
                            if (CFDictionaryGetValueIfPresent ( oneMutTrustSetting,
                                                                kSecTrustSettingsResult,
                                                                (const void**)&numberRef ))
                            {
                                // Record that we have got this policy so it doesn't need
                                // to be created later
                                onePolicyAction->handled = true;
                                
                                // Get the value
                                SecTrustSettingsResult trustSettingResult;
                                CFNumberGetValue ( numberRef,
                                                   kCFNumberSInt32Type,
                                                   &trustSettingResult);
                                
                                // Is the trusted value what we want it to be?
                                SecTrustSettingsResult    newTrustStatus;
                                if (onePolicyAction->action == kTrust)
                                    newTrustStatus    = kSecTrustResultConfirm;
                                else
                                    newTrustStatus    = kSecTrustResultDeny;
                                if (trustSettingResult != newTrustStatus)
                                {
                                    // it isn't so change it
                                    trustSettingResult = newTrustStatus;
                                    numberRef = CFNumberCreate(NULL,
                                                               kCFNumberSInt32Type,
                                                               &trustSettingResult);
                                    
                                    CFDictionaryReplaceValue (oneMutTrustSetting,
                                                              kSecTrustSettingsResult,
                                                              numberRef);
                                    
                            // Mark the certificate as needing saving back to the keychain
                                    trustSettingsDirty = TRUE;
                                }                            
                            }                            
                        }
                    }
                }
            }
        }
    }
    
    // -------- If it hasn't got all the policies, add them ----------
    onePolicyAction = policyActionsHead;
    while (onePolicyAction)
    {
        if (    ( onePolicyAction->action != kRemove)
            &&    (!onePolicyAction->handled))
        {
            // Create policy ref (by searching then getting the first)
            SecPolicyRef policyRef = NULL;
            SecPolicySearchRef policySearchRef = NULL;
            
            result = SecPolicySearchCreate ( CSSM_CERT_X_509v3,
                                             onePolicyAction->policy,
                                             NULL,
                                            &policySearchRef );
            if (result == noErr)
                result = SecPolicySearchCopyNext (  policySearchRef, &policyRef );
                
            if (result == noErr)
            {
                // Create the constraints dictionary
                CFMutableDictionaryRef oneMutTrustSetting
                                         = CFDictionaryCreateMutable(
                                                         NULL, 0,
                                                        &kCFTypeDictionaryKeyCallBacks,
                                                        &kCFTypeDictionaryValueCallBacks);
                
                // Add the policy we're interested in
                CFDictionaryAddValue(oneMutTrustSetting, kSecTrustSettingsPolicy, policyRef);
                
                // Create and add the policies trusted status
                SecTrustSettingsResult    newTrustStatus;
                if (onePolicyAction->action == kTrust)
                    newTrustStatus    = kSecTrustResultConfirm;
                else
                    newTrustStatus    = kSecTrustResultDeny;
                CFNumberRef resultType = CFNumberCreate(NULL,
                                                        kCFNumberSInt32Type,
                                                        &newTrustStatus);
                CFDictionaryAddValue(oneMutTrustSetting, kSecTrustSettingsResult, resultType);
                
                // Add the dictionary to the array
                CFArrayAppendValue ( trustSettingMutArray, oneMutTrustSetting);
                
                // Mark the certificate as needing saving back to the keychain
                trustSettingsDirty = TRUE;
            }
            
            if (policyRef)
                CFRelease(policyRef);
            if (policySearchRef)
                CFRelease(policySearchRef); 

        }
        onePolicyAction = onePolicyAction->nextAction;
    }
    
    // -------- Write certificate back to the keychain (if it's changed) ----------
    if (    (result == noErr)
        &&    trustSettingsDirty)
    {        
        result = SecTrustSettingsSetTrustSettings(certificateRef,
                                                  kSecTrustSettingsDomainUser,
                                                  trustSettingMutArray );
    }
    
    // -------- Clean up ---------
    if (trustSettingMutArray)
        CFRelease(trustSettingMutArray);
    if (trustSettingArray)
        CFRelease(trustSettingArray);

    return result;
}



// --------------------------------------------------------
// compareOids
// --------------------------------------------------------
CSSM_BOOL compareOids( const CSSM_OID *oid1,
                             const CSSM_OID *oid2)
{
    if((oid1 == NULL) || (oid2 == NULL)) 
        return CSSM_FALSE;
    
    if(oid1->Length != oid2->Length)
        return CSSM_FALSE;
    
    if(memcmp(oid1->Data, oid2->Data, oid1->Length))
        return CSSM_FALSE;
   
    return CSSM_TRUE;
}
