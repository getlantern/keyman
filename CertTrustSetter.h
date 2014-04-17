/*
*  CertTrustSetter.h
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

#ifndef _CertTrustSetter_H_
#define _CertTrustSetter_H_  1

#include <Security/security.h>

#ifdef __cplusplus
extern "C" {
#endif

enum PolicyStateAction {
     kTrust = 0,
     kDeny,
     kRemove
};

typedef struct TrustPolicyAction TrustPolicyAction;
struct TrustPolicyAction {
     const CSSM_OID*     policy;     // Policy to set
     int               action;     // What it is set to
     bool               handled;     // Private : Default to false
     TrustPolicyAction*     nextAction;     // Next item in the list
};

     
OSStatus addCertificateWithBytes(const uint8* bytes, int length,
                              SecCertificateRef* returnCertRef);
     
OSStatus trustCertificate(const SecCertificateRef  certificateRef,
                              TrustPolicyAction* policyActionsHead );

     
#ifdef __cplusplus
}
#endif

#endif