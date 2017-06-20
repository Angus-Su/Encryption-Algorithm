

  
#ifndef ENCRYPTION_H
#define ENCRYPTION_H
/* ===========================================================================
 *
 *   Name:       ciper_init_aes
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void ciper_init_aes(unsigned char key_size);

/* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void cipher_aes(unsigned char *in, unsigned char *out);

/* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void inv_cipher_aes(unsigned char *in, unsigned char *out);

/* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void key_expansion_aes(unsigned char *key);


 
 /* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void CreatSecurityKeyLevel_1(unsigned char _gSeed[],unsigned char _Security[]);

/* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void CreatSecurityKeyLevel_2(unsigned char _gSeed[],unsigned char _Security[]);

/* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void CreatSecurityKey_Supplier(unsigned char _gSeed[],unsigned char _Security[]);

/* ===========================================================================
 *
 *   Name:       LIN_Task
 *
 *   Function:   Process the LIN stack
 *
 *   Inputs:     None
 *
 *   Outputs:    None
 *
 *   Return:     None
 *
 *   Side Effects:
 *
 *   Remarks:    This function must be called immediately after CAN_Task()
 *
 * ========================================================================= */
void GenKey(unsigned char RandomData[],unsigned char RequestType,unsigned char RequestPara[],unsigned char TboxEnF1Prm,unsigned char ReponseData[],unsigned char ImmoDATA[]);

#endif