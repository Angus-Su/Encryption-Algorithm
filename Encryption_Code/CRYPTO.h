/*---------------------------------------------------------------------------*/
/*                                                                           */
/* Copyright (C), Phillips Semiconductors PCALH                              */
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
/* FILE:    CRYPTO.H                                                         */
/* Author:  Frank Schlüter                                                   */
/*---------------------------------------------------------------------------*/
/* References:                                                               */
/*                                                                           */
/* SECT-DESIGN      Design Specification - Security Software for PCF79735    */
/*                  Author: Frank Schlüter Report: HAC/CC95011               */
/* SECT-ALG         Security Algorithm for PCF79735 report 21.07.95          */
/* SECT-TUT-C       Tutorial Software - C Security algorithm for PCF79735    */
/*                  Security Transponder 07.08.95 Report No.:   HAC/CC95006  */
/* SECT-TUT-ASM     Tutorial Software - Assembler - Algorithm for PCF79735   */
/*                  Security Transponder                                     */
/*---------------------------------------------------------------------------*/
/* Date      |       CHANGES DONE                                  | By      */
/*---------------------------------------------------------------------------*/
/* 24.08.95  | Start                                               | FS      */
/*---------------------------------------------------------------------------*/
/* Description                                                               */
/* Header file for module crypto.c with function prototype of CalcResponse   */
/* and the global variables for data transfer to the crypto algorithm        */
/*---------------------------------------------------------------------------*/
#ifndef __CRYPTO_H
#define __CRYPTO_H

/*---------------------------------------------------------------------------*/
/* Global variables for data exchange from/to calling routine                */
/* The names of the variables are oriented at the SECT-ALG report            */
/*---------------------------------------------------------------------------*/
extern unsigned char    A[4];       /* first 4 bytes authenticator */
extern unsigned char    P[29];      /* P sequence */
extern unsigned char    H[6];       /* Challenge vector */ 
extern unsigned char    E[6];       /* Response vector */
             
/*---------------------------------------------------------------------------*/
/* Function prototype for the security algorithm calculation function        */
/*---------------------------------------------------------------------------*/
extern void CalcResponse(void);


#endif
