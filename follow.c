#include <dlfcn.h>
#include <stdio.h>
#include "seccomon.h"
#include "secmod.h"
#include "secmodi.h"
#include "secmodti.h"
#include "pkcs11.h"
#include "pkcs11t.h"
#include "pk11func.h"
#include "key.h"
#include "secitem.h"
#include "secerr.h"
#include "sslerr.h"

                                 
typedef struct _KeyTypes {       
    CK_KEY_TYPE keyType;         
    CK_MECHANISM_TYPE mechType;  
    CK_MECHANISM_TYPE wrapMech;  
    char *label;                 
} KeyTypes;                      


void                                   
printBuf(unsigned char *data, int len) 
{                                      
    int i;                             
                                       
    for (i=0; i < len; i++) {          
        printf("%02x",data[i]);        
    }                                  
}                                      
                                       



static KeyTypes keyArray[] = {
#ifdef RECOGNIZE_ASYMETRIC_TYPES
    { CKK_RSA, CKM_RSA_PKCS, CKM_RSA_PKCS, "rsa" },
    { CKK_DSA, CKM_DSA, CKM_INVALID_MECHANISM, "dsa" },
    { CKK_DH, CKM_DH_PKCS_DERIVE, CKM_INVALID_MECHANISM, "dh" },
    { CKK_EC, CKM_ECDSA, CKM_INVALID_MECHANISM, "ec" },
    { CKK_X9_42_DH, CKM_X9_42_DH_DERIVE, CKM_INVALID_MECHANISM, "x9.42dh" },
    { CKK_KEA, CKM_KEA_KEY_DERIVE, CKM_INVALID_MECHANISM, "kea" },
#endif
    { CKK_GENERIC_SECRET, CKM_SHA_1_HMAC, CKM_INVALID_MECHANISM, "generic" },
    { CKK_RC2, CKM_RC2_CBC, CKM_RC2_ECB,"rc2" },
    /* don't define a wrap mech for RC-4 since it's note really safe */
    { CKK_RC4, CKM_RC4, CKM_INVALID_MECHANISM, "rc4" }, 
    { CKK_DES, CKM_DES_CBC, CKM_DES_ECB,"des" },
    { CKK_DES2, CKM_DES2_KEY_GEN, CKM_DES3_ECB, "des2" },
    { CKK_DES3, CKM_DES3_KEY_GEN, CKM_DES3_ECB, "des3" },
    { CKK_CAST, CKM_CAST_CBC, CKM_CAST_ECB, "cast" },
    { CKK_CAST3, CKM_CAST3_CBC, CKM_CAST3_ECB, "cast3" },
    { CKK_CAST5, CKM_CAST5_CBC, CKM_CAST5_ECB, "cast5" },
    { CKK_CAST128, CKM_CAST128_CBC, CKM_CAST128_ECB, "cast128" },
    { CKK_RC5, CKM_RC5_CBC, CKM_RC5_ECB, "rc5" },
    { CKK_IDEA, CKM_IDEA_CBC, CKM_IDEA_ECB, "idea" },
    { CKK_SKIPJACK, CKM_SKIPJACK_CBC64, CKM_SKIPJACK_WRAP, "skipjack" },
    { CKK_BATON, CKM_BATON_CBC128, CKM_BATON_WRAP, "baton" },
    { CKK_JUNIPER, CKM_JUNIPER_CBC128, CKM_JUNIPER_WRAP, "juniper" },
    { CKK_CDMF, CKM_CDMF_CBC, CKM_CDMF_ECB, "cdmf" },
    { CKK_AES, CKM_AES_CBC, CKM_AES_ECB, "aes" },
    { CKK_CAMELLIA, CKM_CAMELLIA_CBC, CKM_CAMELLIA_ECB, "camellia" },
};

static int keyArraySize = sizeof(keyArray)/sizeof(keyArray[0]);


static SECStatus (*next_encrypt)(PK11SymKey *,
                       CK_MECHANISM_TYPE mechanism, SECItem *param,
                       unsigned char *out, unsigned int *outLen,
                       unsigned int maxLen,
                       const unsigned char *data, unsigned int dataLen) = NULL;

SECStatus PK11_Encrypt(PK11SymKey *symKey,                                             
                       CK_MECHANISM_TYPE mechanism, SECItem *param,                    
                       unsigned char *out, unsigned int *outLen,                       
                       unsigned int maxLen,                                            
                       const unsigned char *data, unsigned int dataLen){
    if (next_encrypt == NULL) {
        next_encrypt = dlsym(RTLD_NEXT, "PK11_Encrypt");
    }

    SECStatus ret = next_encrypt(symKey, mechanism, param,out,outLen,maxLen,data,dataLen);
   

   /* printf("LEN %d\n",symKey->data.len);
    PK11SlotInfo *slot = symKey->slot;                                                 
    CK_MECHANISM mech = {0, NULL, 0 };                                                 
    CK_ULONG len = maxLen;                                                             
    PRBool owner = PR_TRUE;                                                            
    CK_SESSION_HANDLE session;                                                         
    PRBool haslock = PR_FALSE;                                                         
    CK_RV crv;                                                                         
                                                                                       
    mech.mechanism = mechanism;                                                        
    if (param) {                                                                       
        mech.pParameter = param->data;                                                 
        mech.ulParameterLen = param->len;                                              
    }                                                                                  
                                                                                       
    session = pk11_GetNewSession(slot, &owner);                                        
    haslock = (!owner || !slot->isThreadSafe);                                         
    if (haslock) PK11_EnterSlotMonitor(slot);                                          
    crv = PK11_GETTAB(slot)->C_EncryptInit(session, &mech, symKey->objectID);          
    if (crv != CKR_OK) {                                                               
        if (haslock) PK11_ExitSlotMonitor(slot);                                       
        pk11_CloseSession(slot,session,owner);                                         
        PORT_SetError( PK11_MapError(crv) );                                           
        return SECFailure;                                                             
    }                                                                                  
    crv = PK11_GETTAB(slot)->C_Encrypt(session, (unsigned char *)data,                 
                                       dataLen, out, &len);                            
    if (haslock) PK11_ExitSlotMonitor(slot);                                           
    pk11_CloseSession(slot,session,owner);                                             
    *outLen = len;                                                                     
    if (crv != CKR_OK) {                                                               
        PORT_SetError( PK11_MapError(crv) );                                           
        return SECFailure;                                                             
    }  
*/



static CK_RV (*seckeycrypt)(CK_FUNCTION_LIST_PTR pFunctionList,                            
                      CK_SESSION_HANDLE hSession,                                      
                       CK_OBJECT_HANDLE hSymKey, CK_MECHANISM *cryptMech,              
                       const CK_BYTE *  pData, CK_ULONG dataLen)= NULL;

CK_RV PKM_SecKeyCrypt(CK_FUNCTION_LIST_PTR pFunctionList,                              
                      CK_SESSION_HANDLE hSession,                                      
                       CK_OBJECT_HANDLE hSymKey, CK_MECHANISM *cryptMech,              
                       const CK_BYTE *  pData, CK_ULONG dataLen) {
    if (seckeycrypt == NULL) {                                                         
        seckeycrypt = dlsym(RTLD_NEXT, "PKM_SecKeyCrypt");                                
    }     
	print("SEC \n");
	return seckeycrypt( pFunctionList,
                       hSession,
                        hSymKey, cryptMech,
                        pData,  dataLen);
	
}




/*
 
    //if(ret == 0){ // data,dataLen
		char * k = (char*)(((PK11SymKeyStr*)symKey)->data.data);
		int len =  ((PK11SymKeyStr*)symKey)->size	;
		//char *key = (char*)(symKey->data);
		int i = 0;
		printf("PTR : %p\n",k);

		printf("KEY ");
		for(i=0;i<len;i++){
			printf(" %d",k[i]);
		}
		printf("len = %d\n\n",len);
		
   // }

SECStatus ret = next_encrypt(symKey, mechanism, param,out,outLen,maxLen,data,dataLen);   
*/
    return ret;
}
CK_RV pk11_notify(CK_SESSION_HANDLE session, CK_NOTIFICATION event,
                                                         CK_VOID_PTR pdata)
{                 
    return CKR_OK;
}                                                  
    
CK_SESSION_HANDLE
GetNewSession(PK11SlotInfo *slot,PRBool *owner) 
{                                    
    CK_SESSION_HANDLE session;
    *owner =  PR_TRUE;                         
    if (!slot->isThreadSafe) PK11_EnterSlotMonitor(slot);
    if ( PK11_GETTAB(slot)->C_OpenSession(slot->slotID,CKF_SERIAL_SESSION,
                        slot,pk11_notify,&session) != CKR_OK) { 
        *owner = PR_FALSE;      
        session = slot->session;
    }               
    if (!slot->isThreadSafe) PK11_ExitSlotMonitor(slot);
                                                                   
    return session;                                 
}        



const char *
GetStringFromKeyType(CK_KEY_TYPE type)
{
    int i;
    for (i=0; i < keyArraySize; i++) {
        if (keyArray[i].keyType == type) {
            return keyArray[i].label;
        }
    }
    return "unmatched";
}







SECStatus (*next_decrypt)(PK11SymKey *symkey,
                       CK_MECHANISM_TYPE mechanism, SECItem *param,
                       unsigned char *out, unsigned int *outLen,
                       unsigned int maxLen,
                       const unsigned char *enc, unsigned int encLen) = NULL;

SECStatus PK11_Decrypt(PK11SymKey *symkey,
		       CK_MECHANISM_TYPE mechanism, SECItem *param,
		       unsigned char *out, unsigned int *outLen,
		       unsigned int maxLen,
		       const unsigned char *enc, unsigned int encLen){


  PK11SlotInfo *slot = symkey->slot;                                                 
    CK_MECHANISM mech = {0, NULL, 0 };                                                 
  //  CK_ULONG len = maxLen;                                                             
    PRBool owner = PR_TRUE;                                                            
    CK_SESSION_HANDLE session;                                                         
    PRBool haslock = PR_FALSE;                                                         
    CK_RV crv;       


    if (next_decrypt == NULL) {
        next_decrypt = dlsym(RTLD_NEXT, "PK11_Decrypt");
    }

/*
  typedef struct PK11SymKeyStr KEY;
	*/
//	PK11SlotInfo *slot = symkey->slot;

  /*  mech.mechanism = mechanism;
    if (param) {
        mech.pParameter = param->data;
        mech.ulParameterLen = param->len;
    }                                                                                  
                                                                                       
    session = GetNewSession(slot, &owner);                                        
    haslock = (!owner || !slot->isThreadSafe);                                         
    if (haslock) PK11_EnterSlotMonitor(slot);                                          
    crv = PK11_GETTAB(slot)->C_DecryptInit(session, &mech, symkey->objectID);          
    if (crv != CKR_OK) {                                                               
        if (haslock) PK11_ExitSlotMonitor(slot);                                       
        pk11_CloseSession(slot, session, owner);                                       
        PORT_SetError( PK11_MapError(crv) );                                           
        return SECFailure;                                                             
    }     
	CK_RV crv = PK11_GETTAB(slot)->C_UnwrapKey(rwsession, &mechanism,
newKey->objectID,
wrappedKey->data,
wrappedKey->len, keyTemplate,
templateCount, &privKeyID);
 

	//CK_RV rv = PK11_GETTAB(slot)->C_UnwrapKey(session,&mech,); 


        int i = mech.ulParameterLen;
	printf("some %d\n",i);

	for ( i = 0; i < mech.ulParameterLen; i++){
		printf(" %x",param->data[i]);
	}		




*/



char *name = PK11_GetSymKeyNickname(symkey);          
int len = PK11_GetKeyLength(symkey);                  
int strength = PK11_GetKeyStrength(symkey, NULL);     
SECItem *value = NULL;                                
CK_KEY_TYPE type = PK11_GetSymKeyType(symkey);        
(void) PK11_ExtractKeyValue(symkey);                  




 value = PK11_GetKeyData(symkey);                                            
                                                                             
 printf("%-20s %3d   %4d   %10s  ", name ? name: " ", len, strength,         
                             GetStringFromKeyType(type));                    
 if (value && value->data) {                                                 
     printBuf(value->data, value->len);                                      
 } else {                                                                    
     printf("<restricted>");                                                 
 }                                                                           
 printf("\n");                                                               







	
//	printf("\n");
      //  if(symkey != NULL)
              //  printf("DLEN : %d\n",((KEY*)symkey)->data.len);
	
//printf("HERE\n");
    SECStatus ret = next_decrypt(symkey,mechanism,param,out,outLen,maxLen,enc,encLen);
   /* if(ret == 0){

	typedef struct PK11SymKeyStr KEY;

	if(symkey != NULL)
		printf("DLEN : %d\n",((KEY*)symkey)->data.len);
    }
*/
    return ret;
}

