/*---------------------------------------------------------------------------*/
/*                                                                           */
/* Copyright (C), Philips Semiconductors PCALH                               */
/*                                                                           */
/*---------------------------------------------------------------------------*/
/*                       (C) Philips Electronics N. V. 1995                  */
/* All rights are reserved. Reproduction in whole or in part is prohibited   */
/*             without the written consent of the copyright owner.           */
/*                                                                           */
/*  Philips reserves the right to make changes without notice at any time.   */
/* Philips makes no warranty, expressed, implied or statutory, including but */
/* not limited to any implied warranty of merchantibility or fitness for any */
/*   particular purpose, or that the use will not infringe any third party   */
/* patent,copyright or trademark. Philips must not be liable for any loss or */
/*                       damage arising from its use.                        */
/*---------------------------------------------------------------------------*/
/* Philips GmbH Roehren- und Halbleiterwerke                                 */
/* Product Concept & Application Laboratory Hamburg                          */
/* ACS-ID                                                                    */
/*---------------------------------------------------------------------------*/
/* Name of the Project:                                                      */
/*                                                                           */
/* FILE:    CRYPTO.C                                                         */
/* Authors:     Frank Schlueter (FS), Oliver Kuehnbach (OK)                  */
/*---------------------------------------------------------------------------*/
/* References:                                                               */
/*                                                                           */
/* SECT-DESIGN      Design Specification - Security Software for PCF79735    */
/*                  Author: Frank Schlueter Report: HAC/CC95011              */
/* SECT-ALG         Security Algorithm for PCF79735 report 21.07.95          */
/* SECT-TUT-C       Tutorial Software - C Security algorithm for PCF79735    */
/*                  Security Transponder 07.08.95 Report No.:   HAC/CC95006  */
/* SECT-TUT-ASM     Tutorial Software - Assembler - Algorithm for PCF79735   */
/*                  Security Transponder                                     */
/*---------------------------------------------------------------------------*/
/* Date      |       CHANGES DONE                                  | By      */
/*---------------------------------------------------------------------------*/
/* 24.08.95  | Start                                               | FS      */
/* 02.09.95  | Optimizations                                       | OK      */
/*---------------------------------------------------------------------------*/
/* Description                                                               */

/* Security Algorithm for PCF79735 transponder in C                          */
/* Challenge - Response Protocol Security Transponder                        */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Include files                                                             */
/*---------------------------------------------------------------------------*/
#pragma warn_no_side_effect off

#ifdef TARGET_8051
#define BOOL bit
#else  
#define BOOL unsigned char
#endif

#ifdef PC_TEST
#include <stdio.h> 
#include <stdlib.h>
#include <stdarg.h>
#endif





/*---------------------------------------------------------------------------*/
/* Redefinition for the const keyword to let the LookupTable stay in the     */
/* code memory of the 8051                                                   */
/* This definition have to be made before including the file perm_c.h        */
/*---------------------------------------------------------------------------*/
#ifdef TARGET_8051
#define const   code
#endif

#include "PERM_C.H"

/*---------------------------------------------------------------------------*/
/* Local Prototypes                                                          */
/*---------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------*/
/* Imported Variables                                                        */
/*---------------------------------------------------------------------------*/
/* none */


/*---------------------------------------------------------------------------*/
/* Local variables                                                           */
/* The names of the variables are oriented at the SECT-ALG report            */
/*---------------------------------------------------------------------------*/
static unsigned char   U0;             /* U byte 0 */
static unsigned char   U1;             /* U byte 1 */
static unsigned char   U2;             /* U byte 2 */
static unsigned char   U3;             /* U byte 3 */

static unsigned char   RB;             /* 8 bit feedback value */
static unsigned char   PIndex;         /* Current P index */
static BOOL            HBit;           /* Current H value */

/*---------------------------------------------------------------------------*/
/* Global variables for data exchange from/to calling routine                */
/* The names of the variables are oriented at the SECT-ALG report            */
/*---------------------------------------------------------------------------*/
static unsigned char   A[4];           /* first 4 bytes authenticator */
static unsigned char   P[29];          /* P sequence */
static unsigned char   H[6];           /* Challenge vector */ 
static unsigned char   E[6];           /* Response vector */
 
#ifdef TARGET_8051
/* type of memory - here: internal data - is specified */
/* to optimize the pointer access */
typedef unsigned char data      *TPointerToResponseByte;
#else
typedef unsigned char           *TPointerToResponseByte;
#endif



                
                 
/*---------------------------------------------------------------------------*/
/* Local Constants                                                           */
/*---------------------------------------------------------------------------*/


/* ROM tables to mask bits 0 to 7. */
/* the following table is to be indexed by tab[7-bitn], */
/* i.e. tab[0] holds the mask for the MSB */

static const unsigned char tabBitMask_1to8[9] = 
{
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80
};

#define GetBitMask_1to8(bit)     (tabBitMask_1to8[(bit)])


/*---------------------------------------------------------------------------*/
/*  To get debug output in PC_TEST mode define DEBUG with debuglevel         */
/*---------------------------------------------------------------------------*/
/* #define DEBUG    10   */

/*---------------------------------------------------------------------------*/
/*  To calculate 48 bit response define CHALLENGE_48, else 32 bit are        */
/*  calculated                                                               */
/*---------------------------------------------------------------------------*/
#define CHALLENGE_48

/*---------------------------------------------------------------------------*/
/* Constant definition for masking the response bits inside Phi2             */
/*---------------------------------------------------------------------------*/
#define E0_MASK     128     /*  Mask for Response Bit E0 in U0 => Z0 */                    
#define E1_MASK     64      /*  Mask for Response Bit E1 in U0 => Z4 */                    


/*---------------------------------------------------------------------------*/
/* Macros                                                                    */
/*---------------------------------------------------------------------------*/


/* rotate a variable one bit right, the LSB becomes the new MSB */
#define cror1(var)  {if( var & 1 ) var = 0x80 + (var >> 1); else var = var >> 1;}




/*---------------------------------------------------------------------------*/
/* Variables for DEBUG mode only                                             */
/*---------------------------------------------------------------------------*/
#ifdef DEBUG
    unsigned int    Nr;             /* The round number */
    char            Buffer[40];     /* String buffer for debugging */
    char            Buffer2[40];    /* String buffer for debugging */
    

/*---------------------------------------------------------------------------*/        
/* Writes binary string representation of data with given length to output   */
/* buffer                                                                    */
/*                                                                           */
/* Use this function only in debugmode when DEBUG is defined                 */
/*---------------------------------------------------------------------------*/
char* Bin( int  data, int len, char* out )
{
    int         i;
                         
    out[0] = '\0';
    for( i=len-1; i>=0; i-- )
    {
        if( data & (1<<i) )
        {
            sprintf( out, "%s1", out );
        }
        else
        {
            sprintf( out, "%s0", out );
        }
    }   
    return out;
}     
              
/*---------------------------------------------------------------------------*/        
/* Output function for debug strings in printf style with debuglevel         */
/*                                                                           */
/* Use this function only in debugmode when DEBUG is defined                 */
/*---------------------------------------------------------------------------*/
void Debug( int Level, char* format, ... )
{
    va_list     va;
    char        Buffer[256];
    FILE*       Log;
    
    va_start(  va, format );
    vsprintf( Buffer, format, va );
    if( Level <= DEBUG ) 
    {
        Log = fopen( "logfile.txt", "a" );  
        
        if( Log != NULL )
        {    
            fprintf( Log, Buffer );
            fflush( Log );
            fclose( Log );
        }                
        else
        {
            printf( "Could not open: logfile.txt\n" );
        }
    }
}
              
/*---------------------------------------------------------------------------*/        
/*  Show the current status of the U bytes and the ZC inputs to the function */
/*  blocks                                                                   */
/*                                                                           */
/* Use this function only in debugmode when DEBUG is defined                 */
/*---------------------------------------------------------------------------*/
void ShowStatus( )
{        
    char        Status[128];

    sprintf( Status, "%4d ", Nr );
    
    if( ZC0_U_BYTE & ZC0_U_BIT_MASK )
    {
        sprintf( Status, "%s|1", Status );
    }
    else
    {
        sprintf( Status, "%s|0", Status );  
    }
    if( ZC1_U_BYTE & ZC1_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC2_U_BYTE & ZC2_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC3_U_BYTE & ZC3_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC4_U_BYTE & ZC4_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC5_U_BYTE & ZC5_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC6_U_BYTE & ZC6_U_BIT_MASK )
    {
        sprintf( Status, "%s|1|", Status );
    }
    else
    {
        sprintf( Status, "%s|0|", Status ); 
    }
    if( ZC7_U_BYTE & ZC7_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC8_U_BYTE & ZC8_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC9_U_BYTE & ZC9_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC10_U_BYTE & ZC10_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC11_U_BYTE & ZC11_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC12_U_BYTE & ZC12_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC13_U_BYTE & ZC13_U_BIT_MASK )
    {
        sprintf( Status, "%s|1|", Status );
    }
    else
    {
        sprintf( Status, "%s|0|", Status ); 
    }
    if( ZC14_U_BYTE & ZC14_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC15_U_BYTE & ZC15_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC16_U_BYTE & ZC16_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC17_U_BYTE & ZC17_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC18_U_BYTE & ZC18_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC19_U_BYTE & ZC19_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC20_U_BYTE & ZC20_U_BIT_MASK )
    {
        sprintf( Status, "%s|1|", Status );
    }
    else
    {
        sprintf( Status, "%s|0|", Status ); 
    }
    if( ZC21_U_BYTE & ZC21_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC22_U_BYTE & ZC22_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC23_U_BYTE & ZC23_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC24_U_BYTE & ZC24_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC25_U_BYTE & ZC25_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC26_U_BYTE & ZC26_U_BIT_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( ZC27_U_BYTE & ZC27_U_BIT_MASK )
    {
        sprintf( Status, "%s|1|", Status );
    }
    else
    {
        sprintf( Status, "%s|0|", Status );  
    }

    sprintf( Status, "%s Response[", Status );

    if( RB & R0_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R1_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R2_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R3_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R4_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R5_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R6_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    if( RB & R7_MASK )
    {
        sprintf( Status, "%s1", Status );
    }
    else
    {
        sprintf( Status, "%s0", Status );   
    }
    

    sprintf( Status, "%s] ", Status );

    sprintf( Status, "%s RB[%s]", Status, Bin( RB, 8, Buffer ) );
    sprintf( Status, "%s U[%2X %2X %2X %2X]", Status, U0, U1, U2, U3 );
    Debug( 0, Status );         
}                                        

/*---------------------------------------------------------------------------*/
/* Get the output RB2N RB2N+1 of Auth function block F0...F3 at normed index */
/*                                                                           */
/* Input:   Nr                                                               */
/*                                                                           */
/* Nr:      Number of functional block 0..3 for F0..F3                       */
/* Index:   Normed index of input vector                                     */
/* Out:     Number of output 0 or 1                                          */
/*                                                                           */
/* Use this function only in debugmode when DEBUG is defined                 */
/* This function is internaly used from ShowF()                              */
/*---------------------------------------------------------------------------*/
int GetF( int Nr, int Index, int Out )
{
    int     FIndex;
    int     R0Mask;
    int     R1Mask;
    
    FIndex = 0;
    
    switch( Nr )
    {
        case 0:    
            R0Mask = R0_MASK;
            R1Mask = R1_MASK;
            
            if( Index & (1<<NORMED_EXOR_OUT) )
            {
                FIndex |= F0_ZC6_MASK;
            }
            if( Index & (1<<NORMED_CARRY_IN) )
            {
                FIndex |= F0_CARRY_IN_MASK;
            }
            if( Index & (1<<5) )
            {
                FIndex |= ZC0_U_BIT_MASK;
            }
            if( Index & (1<<4) )
            {
                FIndex |= ZC1_U_BIT_MASK;
            }
            if( Index & (1<<3) )
            {
                FIndex |= ZC2_U_BIT_MASK;
            }
            if( Index & (1<<2) )
            {
                FIndex |= ZC3_U_BIT_MASK;
            }
            if( Index & (1<<1) )
            {
                FIndex |= ZC4_U_BIT_MASK;
            }
            if( Index & (1<<0) )
            {
                FIndex |= ZC5_U_BIT_MASK;
            }
            break;
        case 1:
            R0Mask = R2_MASK;
            R1Mask = R3_MASK;
            
            if( Index & (1<<NORMED_EXOR_OUT) )
            {
                FIndex |= F1_ZC13_MASK;                      
            }
            if( Index & (1<<NORMED_CARRY_IN) )
            {
                FIndex |= F1_CARRY_IN_MASK;
            }
            if( Index & (1<<5) )
            {
                FIndex |= ZC7_U_BIT_MASK;
            }
            if( Index & (1<<4) )
            {
                FIndex |= ZC8_U_BIT_MASK;
            }
            if( Index & (1<<3) )
            {
                FIndex |= ZC9_U_BIT_MASK;
            }
            if( Index & (1<<2) )
            {
                FIndex |= ZC10_U_BIT_MASK;
            }
            if( Index & (1<<1) )
            {
                FIndex |= ZC11_U_BIT_MASK;
            }
            if( Index & (1<<0) )
            {
                FIndex |= ZC12_U_BIT_MASK;
            }
            break;
        case 2:
            R0Mask = R4_MASK;
            R1Mask = R5_MASK;
            
            if( Index & (1<<NORMED_EXOR_OUT) )
            {
                FIndex |= F2_ZC20_MASK;
            }
            if( Index & (1<<NORMED_CARRY_IN) )
            {
                FIndex |= F2_CARRY_IN_MASK;
            }
            if( Index & (1<<5) )
            {
                FIndex |= ZC14_U_BIT_MASK;
            }
            if( Index & (1<<4) )
            {
                FIndex |= ZC15_U_BIT_MASK;
            }
            if( Index & (1<<3) )
            {
                FIndex |= ZC16_U_BIT_MASK;
            }
            if( Index & (1<<2) )
            {
                FIndex |= ZC17_U_BIT_MASK;
            }
            if( Index & (1<<1) )
            {
                FIndex |= ZC18_U_BIT_MASK;
            }
            if( Index & (1<<0) )
            {
                FIndex |= ZC19_U_BIT_MASK;
            }
            break;
        case 3:
            R0Mask = R6_MASK;
            R1Mask = R7_MASK;
            
            if( Index & (1<<NORMED_EXOR_OUT) )
            {
                FIndex |= F3_ZC27_MASK;
            }
            if( Index & (1<<NORMED_CARRY_IN) )
            {
                FIndex |= F3_CARRY_IN_MASK;
            }
            if( Index & (1<<5) )
            {
                FIndex |= ZC21_U_BIT_MASK;
            }
            if( Index & (1<<4) )
            {
                FIndex |= ZC22_U_BIT_MASK;
            }
            if( Index & (1<<3) )
            {
                FIndex |= ZC23_U_BIT_MASK;
            }
            if( Index & (1<<2) )
            {
                FIndex |= ZC24_U_BIT_MASK;
            }
            if( Index & (1<<1) )
            {
                FIndex |= ZC25_U_BIT_MASK;
            }
            if( Index & (1<<0) )
            {
                FIndex |= ZC26_U_BIT_MASK;
            }
            break;  
        default:
            printf( "ERROR wrong number of functional block: %d\n", Nr );
            break;      
    }                               
    if( Out == 0 )
    {
        if( (LookupTable[FIndex] & R0Mask) !=  0 )
        {
            return 1;
        }           
        else
        {
            return 0;
        }            
    }
    else
    {
        if( (LookupTable[FIndex] & R1Mask) !=  0 )
        {
            return 1;
        }           
        else
        {
            return 0;
        }            
    }
}    

/*---------------------------------------------------------------------------*/
/* Show the F function vector decoded from the generated lookup table        */
/*                                                                           */
/* Use this function only in debugmode when DEBUG is defined                 */
/*---------------------------------------------------------------------------*/
void ShowF( int Nr )
{        
    int     i;           
       
    Debug( 3, "F%d R0[        ]", Nr );
    for( i=0; i<64; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 0 ) );     
    } 
    Debug( 3, "\n" );
    Debug( 3, "F%d R1[        ]", Nr );
    for( i=0; i<64; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 1 ) );     
    } 
    Debug( 3, "\n" );

    Debug( 3, "F%d R0[ IN     ]", Nr );
    for( i=64; i<128; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 0 ) );     
    } 
    Debug( 3, "\n" );
    Debug( 3, "F%d R1[ IN     ]", Nr );
    for( i=64; i<128; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 1 ) );     
    } 
    Debug( 3, "\n" );

    Debug( 3, "F%d R0[ OUT    ]", Nr );
    for( i=128; i<192; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 0 ) );     
    } 
    Debug( 3, "\n" );
    Debug( 3, "F%d R1[ OUT    ]", Nr );
    for( i=128; i<192; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 1 ) );     
    } 
    Debug( 3, "\n" );

    Debug( 3, "F%d R0[ IN OUT ]", Nr );
    for( i=192; i<256; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 0 ) );     
    } 
    Debug( 3, "\n" );
    Debug( 3, "F%d R1[ IN OUT ]", Nr );
    for( i=192; i<256; i++ )
    {
        Debug( 3, "%d", GetF( Nr, i, 1 ) );     
    } 
    Debug( 3, "\n" );
}

#endif  /* #ifdef DEBUG  */
                 
/*---------------------------------------------------------------------------*/
/* LeftRounds function Phi1 similar to the report of the algorithm SECT-ALG. */
/* 17 rounds with one HBit are done inside Phi1 to reduce function calls to  */
/* Phi1                                                                      */
/*                                                                           */
/* The difference between Phi1 and Phi2 is the usage of                      */
/* Auth challenge bit HBit in Phi1.                                          */
/*                                                                           */
/* This function is described in SECT-DESIGN Chapter 5.2.2                   */
/*---------------------------------------------------------------------------*/
static void Phi1()                     
{           
    unsigned char   LeftRounds,temp;
    unsigned char   FIndex;     /* Index in lookup table */
         
#ifdef DEBUG
    unsigned char   F0,F1,F2,F3;  
#endif  
    
    LeftRounds = 17;
    do
    {
        FIndex  = (U0 & U0_MASK_F0);
        FIndex |= (U1 & U1_MASK_F0);
        FIndex |= (U2 & U2_MASK_F0);
        FIndex |= (U3 & U3_MASK_F0);
        
        
        if( HBit)
        {
            FIndex |= ZC2_U_BIT_MASK; 
        }
        else
        {
            FIndex &= ~ZC2_U_BIT_MASK; 
        }
    
#ifdef DEBUG                
        F0 = LookupTable[FIndex] & R0_MASK;
#endif
    
#ifndef  MATCH_EXOUT_F0
        /* Set the address bit for ZC6 in ZC6 = 1 */
        if( (ZC6_U_BYTE & ZC6_U_BIT_MASK) != 0 )
        {                                            
            FIndex |= F0_ZC6_MASK;
        }                  
#endif
        RB      = (LookupTable[FIndex] & F0_RB_MASK);
#ifdef DEBUG
        Debug( 11, "RB[0] = %s Mask: %s\n", 
            Bin( RB, 8, Buffer ), Bin( F0_RB_MASK, 8, Buffer2 ) );
#endif
        
        FIndex  = (U0 & U0_MASK_F1);
        FIndex |= (U1 & U1_MASK_F1);
        FIndex |= (U2 & U2_MASK_F1);
        FIndex |= (U3 & U3_MASK_F1);   
        
#ifdef DEBUG                
        F1 = LookupTable[FIndex] & R2_MASK;
#endif
        
        
#ifndef  MATCH_EXOUT_F1
        /* Set the address bit for ZC13 in ZC13 = 1 */
        if( HBit ^ ((ZC13_U_BYTE & ZC13_U_BIT_MASK) != 0)))
        {
            FIndex |= F1_ZC13_MASK;
        }   
#else
        if( !HBit )
        {         
            /* Invert table index for EXOUT because the table is implicit 
               inverted to optimize Phi2 */
            FIndex ^= F1_ZC13_MASK;
        }



#endif
    
        /* If carry from F0 is set then set F1_CARRY_IN_MASK in Findex */
        if( RB & R1_MASK)
        {
            FIndex |= F1_CARRY_IN_MASK;     
        }
        RB     |= LookupTable[FIndex] & F1_RB_MASK;
#ifdef DEBUG
        Debug( 11, "RB[1] = %s Mask: %s\n", 
            Bin( RB, 8, Buffer ), Bin( F1_RB_MASK, 8, Buffer2 ) );
#endif
        
        FIndex  = (U0 & U0_MASK_F2);
        FIndex |= (U1 & U1_MASK_F2);
        FIndex |= (U2 & U2_MASK_F2);
        FIndex |= (U3 & U3_MASK_F2);  
    
#ifdef DEBUG                
        F2 = LookupTable[FIndex] & R4_MASK;
#endif
    
        if( RB & R3_MASK)
        {
            FIndex |= F2_CARRY_IN_MASK;     
        }
        /* Set the address bit for ZC20 in ZC20 = 1 */
#ifndef  MATCH_EXOUT_F2
        if( ZC20_U_BYTE & ZC20_U_BIT_MASK )
        {
            FIndex |= F2_ZC20_MASK;
        }                
#endif
        RB     |= ( LookupTable[FIndex] & F2_RB_MASK );
#ifdef DEBUG
        Debug( 11, "RB[2] = %s Mask: %s\n", 
            Bin( RB, 8, Buffer ), Bin( F2_RB_MASK, 8, Buffer2 ) );
#endif
        
        FIndex  = (U0 & U0_MASK_F3);
        FIndex |= (U1 & U1_MASK_F3);
        FIndex |= (U2 & U2_MASK_F3);
        FIndex |= (U3 & U3_MASK_F3);  
    
#ifdef DEBUG                
        F3 = LookupTable[FIndex] & R6_MASK;
#endif
    
#ifndef MATCH_EXOUT_F3
        /* Set the address bit for ZC27 in ZC27 = 1 */
        if( ZC27_U_BYTE & ZC27_U_BIT_MASK )
        {
            FIndex |= F3_ZC27_MASK;
        }                  
#endif
        /* If carry from F2 is set then set F3_CARRY_IN_MASK in Findex */
        if( RB & R5_MASK )
        {
            FIndex |= F3_CARRY_IN_MASK;     
        }
        RB     |= ( LookupTable[FIndex] & F3_RB_MASK );
#ifdef DEBUG
        Debug( 11, "RB[3] = %s Mask: %s\n", 
            Bin( RB, 8, Buffer ), Bin( F3_RB_MASK, 8, Buffer2 ) );
#endif

        cror1(U3);

        /* build a new block to have the temp variable locally only. this 
        may help keeping memory requirements small */
        temp = U3 ^ RB ^ P[PIndex];
    
        U3 = U2;       
        U2 = U1;
        U1 = U0;
        U0 = temp;

#ifdef DEBUG
        Nr++;
#endif  
        if( PIndex == 28 )   
        {
            PIndex = 0;
        }
        else
        {
            PIndex++;
        }
#ifdef DEBUG    
        ShowStatus();
        Debug( 3, " F[%d%d%d%d]\n", 
            (int)(F0!=0),
            (int) (F1!=0),
            (int) (F2!=0),
            (int) (F3!=0) );
#endif                                     
    } /* LeftRounds Loop for 17 rounds */
    while (--LeftRounds);
}


/*---------------------------------------------------------------------------*/
/* LeftRounds function Phi2 similar to the report of the algorithm.          */
/* 17 rounds for calculating two response bits with implicit double calls    */
/* are done inside Phi2 to reduce function calls to Phi2                     */
/*                                                                           */
/* The difference between phi1 and phi2 is the usage of                      */
/* Auth challenge bit h in phi1.                                             */
/*                                                                           */
/* This function is described in SECT-DESIGN Chapter 5.2.3                   */
/*---------------------------------------------------------------------------*/
static void Phi2()                     
{           
    unsigned char   temp; 
    unsigned char   LeftRounds;
    BOOL            DoubleRound;
    unsigned char   FIndex;     /* Index in lookup table */
         
#ifdef DEBUG
    unsigned char   F0,F1,F2,F3;  
#endif  
    

    LeftRounds=17;
    do
    {
        DoubleRound=1;
        do  
        {
            FIndex  = (U0 & U0_MASK_F0) |
                      (U1 & U1_MASK_F0) |
                      (U2 & U2_MASK_F0) |
                      (U3 & U3_MASK_F0);

#ifdef DEBUG                
            F0 = LookupTable[FIndex] & R0_MASK ;
#endif
    
#ifndef  MATCH_EXOUT_F0
            /* Set the address bit for ZC6 in ZC6 = 1 */
            if( (ZC6_U_BYTE & ZC6_U_BIT_MASK) != 0 )
            {                                            
                FIndex |= F0_ZC6_MASK;
            }
#endif
            RB      = (LookupTable[FIndex] & F0_RB_MASK);
    
#ifdef DEBUG
            Debug( 11, "RB[0] = %s Mask: %s\n", 
                Bin( RB, 8, Buffer ), Bin( F0_RB_MASK, 8, Buffer2 ) );
#endif
        
            FIndex  = (U0 & U0_MASK_F1) |
                      (U1 & U1_MASK_F1) |
                      (U2 & U2_MASK_F1) |
                      (U3 & U3_MASK_F1);   
        
#ifdef DEBUG                
            F1 = LookupTable[FIndex] & R2_MASK;
#endif
        
        
#ifndef  MATCH_EXOUT_F1
            /* If F1 matches Inversion is done implicit in table */
            /* Set the address bit for ZC13 if ZC13 == 0 (Inverted for Phi2) */
            if( (ZC13_U_BYTE & ZC13_U_BIT_MASK) == 0 )
            {
                FIndex |= F1_ZC13_MASK;
            }                  
#endif
            /* If carry from F0 is set then set F1_CARRY_IN_MASK in Findex */
            if( RB & R1_MASK )
            {
                FIndex |= F1_CARRY_IN_MASK;     
            }
            RB     |= LookupTable[FIndex] & F1_RB_MASK;
#ifdef DEBUG
            Debug( 11, "RB[1] = %s Mask: %s\n", 
                Bin( RB, 8, Buffer ), Bin( F1_RB_MASK, 8, Buffer2 ) );
#endif
        
            FIndex  = (U0 & U0_MASK_F2) |
                      (U1 & U1_MASK_F2) |
                      (U2 & U2_MASK_F2) |
                      (U3 & U3_MASK_F2); 
    
#ifdef DEBUG                
            F2 = LookupTable[FIndex] & R4_MASK;
#endif
    
            if( RB & R3_MASK )
            {
                FIndex |= F2_CARRY_IN_MASK;     
            }
#ifndef  MATCH_EXOUT_F2
            /* Set the address bit for ZC20 in ZC20 = 1 */
            if( (ZC20_U_BYTE & ZC20_U_BIT_MASK) != 0 )
            {
                FIndex |= F2_ZC20_MASK;
            }                  
#endif
            RB     |= ( LookupTable[FIndex] & F2_RB_MASK ); 
#ifdef DEBUG
            Debug( 11, "RB[2] = %s Mask: %s\n", 
                Bin( RB, 8, Buffer ), Bin( F2_RB_MASK, 8, Buffer2 ) );
#endif
        
            FIndex  = (U0 & U0_MASK_F3) |
                      (U1 & U1_MASK_F3) |
                      (U2 & U2_MASK_F3) |
                      (U3 & U3_MASK_F3); 
    
#ifdef DEBUG                
            F3 = LookupTable[FIndex] & R6_MASK;
#endif
    
#ifndef  MATCH_EXOUT_F3
            /* Set the address bit for ZC27 in ZC27 = 1 */
            if( ZC27_U_BYTE & ZC27_U_BIT_MASK )
            {
                FIndex |= F3_ZC27_MASK;
            }
#endif
            /* If carry from F2 is set then set F3_CARRY_IN_MASK in Findex */
            if( RB & R5_MASK )
            {
                FIndex |= F3_CARRY_IN_MASK;     
            }
            RB     |= ( LookupTable[FIndex] & F3_RB_MASK );
#ifdef DEBUG
            Debug( 11, "RB[3] = %s Mask: %s\n", 
                Bin( RB, 8, Buffer ), Bin( F3_RB_MASK, 8, Buffer2 ) );
#endif
    
            cror1(U3);
            temp = U3 ^ RB ^ P[PIndex];
                       
            /* Shift Z bits */                       
            U3 = U2;       
            U2 = U1;
            U1 = U0;
            U0 = temp;
            DoubleRound=!DoubleRound;
        } while(!DoubleRound); /* DoubleRound Loop */
        

#ifdef DEBUG
        Nr++;
#endif  
        if( PIndex == 28 )  
        {
            PIndex = 0;
        }
        else
        {
            PIndex++;
        }
                
#ifdef DEBUG    
        ShowStatus();
        Debug( 3, " F[%d%d%d%d]\n", 
            (int)(F0!=0),
            (int) (F1!=0),
            (int) (F2!=0),
            (int) (F3!=0) );
#endif                                     
    } while(--LeftRounds); /* LeftRounds Loop for 17 rounds */    
}
        

/*---------------------------------------------------------------------------*/
/* Calculate the response to a challenge                                     */
/*                                                                           */
/* Input:  first 4 bytes of authenticator in global vector A[0..3]           */
/*         P sequence with 29 elements                                       */
/*         6 or 4 bytes challenge in 48 or 32 bit mode in global H[0..5]     */
/*                                                                           */
/* Output: 6 or 4 bytes response in 48/32 bit mode in global E[0...5]        */
/*                                                                           */
/* This function is described in SECT-DESIGN Chapter 5.2.1                   */
/*---------------------------------------------------------------------------*/
static void CalcResponse()
{
    unsigned char ByteNo;   /* loop variable */


/*  Setup start conditions */
#ifdef DEBUG                
    Nr      = 0;   
#endif
    PIndex  = 0;            /* Initialize PIndex with 0 */
    RB      = 0;            /* Initialize feedback value RB with 0 */

    /*  Clear Response Vector */           
    E[0]    = 0;
    E[1]    = 0;
    E[2]    = 0;
    E[3]    = 0;
    E[4]    = 0;
    E[5]    = 0;

    U0      = A[3];         /* Initialize U vector with the Authenticator */        
    U1      = A[2];     
    U2      = A[1];     
    U3      = A[0];     



#ifdef DEBUG
    Debug( 3, "Calculate Phi1 for bit0-31\n" );
#endif

    /* First call of first rounds after input of the challenge for bit0-31 */
    for( ByteNo=0; ByteNo!=4; ByteNo++ )
    {   
        unsigned char ByteOfChallenge = H[ByteNo];  /* the challenge's byte */
        unsigned char BitNo;                        /* loop variable */

        BitNo=8;
        do  
        {                         
            /* Calculate H Bit */
            HBit = ByteOfChallenge & GetBitMask_1to8(BitNo);
            Phi1();
        }while(--BitNo);  /* Optimized loop for 8051 DJNZ instruction */    
    }            
    
#ifdef DEBUG
    Debug( 3, "Double call Phi2 for calculating response bit0-31\n" );

#endif


    /* Calculate first response with double call to Phi2 */
    for( ByteNo=0; ByteNo!=4; ByteNo++ )
    {       /* build pointer to the response byte changed in the following loop: */
        TPointerToResponseByte pResponse = &E[ByteNo];
        unsigned char          BitNo;     /* loop variable */

        BitNo=8;
        do
        {                         
            Phi2();
            /* Calculate Response Bits */
            if( (U0 & E0_MASK) != 0 )
            {
                *pResponse |= GetBitMask_1to8(BitNo);
            }
            BitNo--;
            if( (U0 & E1_MASK) != 0 )
            {
                *pResponse |= GetBitMask_1to8(BitNo);
            }
        }while (--BitNo);  /* Optimezed loop for 8051 DJNZ instruction */
    }
#ifdef DEBUG
    Debug( 3, "Calculate Phi1 for bit32-47\n" );
#endif

#ifdef CHALLENGE_48
    /* Second call of first rounds after input of the challenge for bit32-47 */
    /* ByteNo already has the necessary start value 4 */
    for( ; ByteNo!=6; ByteNo++ )
    {   
        /* the challenge's byte to use */
        unsigned char ByteOfChallenge = H[ByteNo];            
        unsigned char BitNo;  /* loop variable */

        BitNo=8;
        do  
        {                         
            /* Calculate H BitNo */
            HBit = ByteOfChallenge & GetBitMask_1to8(BitNo);
            Phi1();
        } while (--BitNo); /* Optimezed loop for 8051 DJNZ instruction */   
    }            
    
    
#ifdef DEBUG
    Debug( 3, "Double call Phi2 for calculating response bit32-47\n" );
#endif
    /* Calculate second response with double call to Phi2 */
    for( ByteNo=4; ByteNo!=6; ByteNo++ )
    {       /* build pointer to the response byte changed in the following loop: */
        TPointerToResponseByte pResponse = & E[ByteNo];                    
        unsigned char          BitNo;  /* loop variable */  

        BitNo=8;
        do
        {                         
            Phi2();
            /* Calculate Response Bits */
            if( (U0 & E0_MASK) != 0 )
            {
                *pResponse |= GetBitMask_1to8(BitNo);
            }
            BitNo--;
            if( (U0 & E1_MASK) != 0 )
            {
                *pResponse |= GetBitMask_1to8(BitNo);
            }
        } while (--BitNo); /* Optimezed loop for 8051 DJNZ instruction */
    }   
#endif  /*  CHALLENGE_48  */
} 

#pragma warn_no_side_effect on
    
