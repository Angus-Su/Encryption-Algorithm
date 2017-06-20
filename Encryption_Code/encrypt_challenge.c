#include "encrypt_test.h"
typedef unsigned char byte;

void CreatSecurityKeyLevel_1(byte _gSeedArray[],byte _SecurityKey[])
{
 //   byte gSeedArray[4];
    long wLastSeed, temp, wTemp, wLSBit, wTop31Bits ,LEVEL3_SECURITY ,LEVEL1_SECURITY ;
    char jj, SB1, SB2, SB3, iterations;
    byte i;
    
    LEVEL1_SECURITY = 0x594E348A;
    LEVEL3_SECURITY = 0xda46f426 ;
    wLastSeed = (_gSeedArray[0] << 24) + (_gSeedArray[1] << 16) + (_gSeedArray[2] << 8) + _gSeedArray[3];
    temp =(long)((LEVEL1_SECURITY & 0x00000800) >> 10) | ((LEVEL1_SECURITY & 0x00200000)>> 21);
    switch (temp) 
    {
        case 0 :wTemp = (char)((wLastSeed & 0xff000000) >> 24);	break;
        case 1 :wTemp = (char)((wLastSeed & 0x00ff0000) >> 16); break;
        case 2 :wTemp = (char)((wLastSeed & 0x0000ff00) >> 8); break;
        case 3 :wTemp = (char)(wLastSeed & 0x000000ff); break;
	}
	SB1 = (char)((LEVEL1_SECURITY & 0x000003FC) >> 2);
    SB2 = (char)(((LEVEL1_SECURITY & 0x7F800000) >> 23)^0xA5);
	SB3 = (char)(((LEVEL1_SECURITY & 0x001FE000) >> 13)^0x5A);
	iterations = (char)(((wTemp ^ SB1) & SB2)  + SB3 );
	for (jj = 0; jj < iterations; jj++) 
    {
		wTemp = ((wLastSeed & 0x40000000)/0x40000000) ^ ((wLastSeed & 0x01000000)/0x01000000) ^ ((wLastSeed & 0x1000)/0x1000) ^ ((wLastSeed & 0x04)/0x04);
		wLSBit = (wTemp & 0x00000001);
		wLastSeed = (long)(wLastSeed << 1);
		wTop31Bits = (long)(wLastSeed & 0xFFFFFFFE);
		wLastSeed = (long)(wTop31Bits | wLSBit);
	}
	if (LEVEL1_SECURITY & 0x00000001) 
    {
	    wTop31Bits = ((wLastSeed & 0x00FF0000) >> 16) | ((wLastSeed & 0xFF000000) >> 8) | ((wLastSeed & 0x000000FF) << 8) | ((wLastSeed & 0x0000FF00) << 16);	
	} 
    else 
    {
		wTop31Bits = wLastSeed;
	}
    wTop31Bits = wTop31Bits ^ LEVEL1_SECURITY;
    for(i=0;i<4;i++)
    {
        _SecurityKey[i]= (byte)(wTop31Bits>>(8*(3-i)));        
    }
    //return wTop31Bits;
}

void CreatSecurityKeyLevel_2(byte _gSeedArray[],byte _SecurityKey[])
{
//    	byte gSeedArray[4];
	long wLastSeed, temp, wTemp, wLSBit, wTop31Bits ,LEVEL3_SECURITY ,LEVEL1_SECURITY ;
	char jj, SB1, SB2, SB3, iterations;
    byte i;
    
    LEVEL1_SECURITY = 0x594E348A;
    LEVEL3_SECURITY = 0xda46f426;
    wLastSeed = (_gSeedArray[0] << 24) + (_gSeedArray[1] << 16) 
                + (_gSeedArray[2] << 8) + _gSeedArray[3];
    temp =(long)((LEVEL3_SECURITY & 0x00000800) >> 10) | ((LEVEL3_SECURITY & 0x00200000)>> 21);
    switch (temp) 
    {
        case 0 : wTemp = (char)((wLastSeed & 0xff000000) >> 24);break;
        case 1 : wTemp = (char)((wLastSeed & 0x00ff0000) >> 16);break;
        case 2 : wTemp = (char)((wLastSeed & 0x0000ff00) >> 8);break;
        case 3 : wTemp = (char)(wLastSeed & 0x000000ff);break;
	}
    SB1 = (char)((LEVEL3_SECURITY & 0x000003FC) >> 2);
    SB2 = (char)(((LEVEL3_SECURITY & 0x7F800000) >> 23)^0xA5);
    SB3 = (char)(((LEVEL3_SECURITY & 0x001FE000) >> 13)^0x5A);
    iterations = (char)(((wTemp ^ SB1) & SB2)  + SB3 );
    for (jj = 0; jj < iterations; jj++) 
    {
        wTemp = ((wLastSeed & 0x40000000)/0x40000000) ^ ((wLastSeed & 0x01000000)/0x01000000) ^ ((wLastSeed & 0x1000)/0x1000) ^ ((wLastSeed & 0x04)/0x04);
        wLSBit = (wTemp & 0x00000001);
        wLastSeed = (long)(wLastSeed << 1);
        wTop31Bits = (long)(wLastSeed & 0xFFFFFFFE);
        wLastSeed = (long)(wTop31Bits | wLSBit);
	}
    if (LEVEL3_SECURITY & 0x00000001) 
    {
        wTop31Bits = ((wLastSeed & 0x00FF0000) >> 16) | ((wLastSeed & 0xFF000000) >> 8) | ((wLastSeed & 0x000000FF) << 8) | ((wLastSeed & 0x0000FF00) << 16);	
    } else 
    {
        wTop31Bits = wLastSeed;
    }
    wTop31Bits = wTop31Bits ^ LEVEL3_SECURITY;
    
    for(i=0;i<4;i++)
    {
        _SecurityKey[i]= (byte)(wTop31Bits>>(8*(3-i)));        
    }
   
    //return wTop31Bits;
}

void CreatSecurityKey_Supplier(byte _gSeedArray[],byte _SecurityKey[])
{
    _SecurityKey[0]= 0x01;
    _SecurityKey[1]= 0x02;
    _SecurityKey[2]= 0x03;
    _SecurityKey[3]= 0x04;
}