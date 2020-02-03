/* Nagravision Syster encoder for hacktv                                 */
/*=======================================================================*/
/* Copyright 2020 Marco Wabbel for AVR-portation                         */
/* Copyright 2020 Alex L. James                                          */
/* Copyright 2018 Philip Heron <phil@sanslogic.co.uk>                    */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <stdio.h>
#include <string.h>
#include "systerdes.h"
#include <avr/pgmspace.h>

/* Key left shift table */
PROGMEM uint8_t const LS[] = { 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1, 0 };

/* The S-boxes */
PROGMEM uint8_t const S[] = {
	0x1F, 0xB0, 0x28, 0xEB, 0xD1, 0x0D, 0x42, 0x7E,	0xC5, 0x59, 0x93, 0x34, 0xA6, 0x6A, 0xFC, 0x87,
	0xB0, 0xE3, 0x17, 0x7D, 0x2B, 0x96, 0xDE, 0x48,	0x0A, 0x34, 0x6C, 0x81, 0xC5, 0x5F, 0xA9, 0xF2,
	0x2E, 0xD0, 0x72, 0xB7, 0x95, 0x0C, 0x48, 0xEB,	0x53, 0x6A, 0xC9, 0x14, 0xAF, 0xF1, 0x36, 0x8D,
	0x8D, 0x4E, 0xB1, 0xE8, 0x6B, 0x35, 0x17, 0xD2,	0xF0, 0x93, 0x56, 0x2F, 0x0C, 0xCA, 0xA9, 0x74,
	0xB2, 0x4F, 0xD4, 0x18, 0x0B, 0xF6, 0x7E, 0x25,	0xC1, 0x3C, 0x6A, 0x83, 0xAD, 0x50, 0x97, 0xE9,
	0xE9, 0xB4, 0x42, 0x27, 0x3E, 0xCB, 0x85, 0x18,	0x56, 0x0A, 0x9F, 0x70, 0xF1, 0xAD, 0x6C, 0xD3,
	0x35, 0xE0, 0x5B, 0x0D, 0x68, 0xD3, 0x96, 0x7A,	0xF9, 0x2E, 0xC2, 0xB1, 0x1F, 0x84, 0xAC, 0x47,
	0x6B, 0x1C, 0x0D, 0xA3, 0xD6, 0x7A, 0x30, 0xC5,	0x84, 0xF1, 0xBE, 0x58, 0xE9, 0x2F, 0x47, 0x92,
	0xD1, 0x34, 0xBD, 0xE3, 0x8B, 0x58, 0x42, 0x9E,	0x7A, 0xAF, 0xC0, 0x05, 0x2C, 0xF6, 0x17, 0x69,
	0xB4, 0xD7, 0xE3, 0x48, 0x5E, 0x21, 0x8D, 0x72,	0x09, 0x60, 0x3F, 0xA6, 0x95, 0xCB, 0xFA, 0x1C,
	0x82, 0x27, 0x14, 0xCA, 0xF9, 0x90, 0x6F, 0x5C,	0xEB, 0xD8, 0x7D, 0xA3, 0x4E, 0x35, 0xB1, 0x06,
	0x5C, 0x90, 0x6F, 0xF9, 0x35, 0x4E, 0x82, 0x27,	0x06, 0xEB, 0xCA, 0x14, 0xA3, 0xD8, 0x7D, 0xB1,
	0x52, 0xF8, 0x6F, 0x16, 0x9C, 0xCB, 0x09, 0xA5,	0xED, 0x27, 0x3A, 0x81, 0x43, 0xB4, 0xD0, 0x7E,
	0x2E, 0x95, 0xB2, 0x6F, 0x79, 0x06, 0xC7, 0xF8,	0x4B, 0xE0, 0xD1, 0x3C, 0xA4, 0x5A, 0x1D, 0x83,
	0x0C, 0xE2, 0x7B, 0x18, 0x90, 0x4D, 0xC7, 0xB1,	0x63, 0x8F, 0xDE, 0x25, 0x39, 0xF6, 0xA4, 0x5A,
	0xF2, 0x17, 0x85, 0x4E, 0x5C, 0xB0, 0x2B, 0xED,	0xA4, 0x79, 0x38, 0x93, 0x6F, 0xCA, 0xD1, 0x06
 };

/* Key expansion table */
PROGMEM uint8_t const C[] = {
 	0x1C, 0x1F, 0x18, 0x0A, 0x12, 0x0E, 0x07, 0x1A,	0x04, 0x15, 0x0B, 0x10, 0x0C, 0x1B, 0x0F, 0x09,
 	0x14, 0x1E, 0x05, 0x0D, 0x17, 0x1D, 0x08, 0x13,	0x3E, 0x33, 0x2C, 0x25, 0x39, 0x30, 0x38, 0x26,
 	0x3C, 0x34, 0x2D, 0x29, 0x36, 0x2B, 0x3A, 0x31,	0x24, 0x3D, 0x3B, 0x3F, 0x28, 0x35, 0x2F, 0x32
};

/* CW expansion table */
PROGMEM uint8_t const E[] ={
 	0x1F, 0x00, 0x01, 0x02, 0x03, 0x44, 0x03, 0x04,	0x05, 0x06, 0x07, 0x68, 0x07, 0x08, 0x09, 0x0A,
 	0x0B, 0x8C, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xB0,	0x0F, 0x10, 0x11, 0x12, 0x13, 0xD4, 0x13, 0x14,
 	0x15, 0x16, 0x17, 0xF8, 0x17, 0x18, 0x19, 0x1A,	0x1B, 0x1C, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
 };

 /* Permuation table */
PROGMEM uint8_t const P[] = {
	0x31, 0x12, 0x50, 0x33, 0x13, 0x21, 0x42, 0x00,	0x51, 0x52, 0x30, 0x43, 0x53, 0x70, 0x22, 0x03,
	0x73, 0x62, 0x41, 0x60, 0x23, 0x20, 0x02, 0x01,	0x61, 0x63, 0x40, 0x32, 0x10, 0x11, 0x71, 0x72,
};

/* Initial key permutation */
PROGMEM uint8_t const kp[] = { 0, 3, 2, 1, 4, 5, 6, 7 };

/* Initial CW permutation */
PROGMEM uint8_t const ip[] = { 4, 0, 5, 1, 6, 2, 7, 3 };

/* Final CW permutation */
PROGMEM uint8_t const fp[] = { 7, 3, 6, 2, 5, 1, 4, 0 };

/* Permutation */
void _permute(uint8_t *in, uint8_t *buffer1, const uint8_t *p)
{
	int i, j;
	uint8_t T[8];

	memcpy(T, in, 8);

	for(j = 7; j >= 0; j-- )
	{
		for(i = 0; i < 8; i++ )
		{
			if(pgm_read_byte(&p[0]) & 3)
			/* Final permutation */
			{
				buffer1[j] = (buffer1[j] << 1) | (T[pgm_read_byte(&p[i])] & 1);
				T[pgm_read_byte(&p[i])] >>= 1;
			}
			else
			/* Initial CW and key permutation */
			{
				buffer1[pgm_read_byte(&p[i])] = (buffer1[pgm_read_byte(&p[i])] >> 1) | (T[j] & 1 ? 0x80 : 0);
				T[j] >>= 1;
			}
		}
	}
}

/* Expansion */
void _expand(const uint8_t *e, uint8_t *data, uint8_t *result)
{
	uint8_t d, i, j;

	memset(result, 0 , 8);

	for(j = 0; j < 8; j++)
	{
		for( i = 6; i > 0; i-- ) {
			result[j] <<= 1;
			d = pgm_read_byte(&e[((7 - j) * 6) + (i - 1)]) & (pgm_read_byte(&e[0]) == 0x1F ? 0x1F : 0xFF);
			if(data[d >> 3] & (1 << (d & 7))) result[j] |= 1;
		}
	}
}

/* Key rotation */
void _key_rotate(uint8_t rounds, uint8_t *k)
{
	uint8_t	i, j;

	/* Rotate each half of key separately */
	for(i = 0; i < pgm_read_byte(&LS[rounds]); i++)
	{
		for(j = 0; j < 3; j++)
		{
			k[j + 0] = k[j + 0] >> 1 | (k[j + 1] & 1) << 7;
			k[j + 4] = k[j + 4] >> 1 | (k[j + 5] & 1) << 7;
		}
		k[3] = k[3] >> 1 | ((k[0] >> 3) & 1) << 7;
		k[7] = k[7] >> 1 | ((k[4] >> 3) & 1) << 7;
	}
}

/* Main DES function */
void _syster_des_f(uint8_t *k, uint8_t *cw)
{
	uint8_t i; //int

	/* Expanded key and control word */
	uint8_t ecw[8], ek[8];

	for(i = 0; i < 16; i++)
	{
		uint8_t c, j; //int

		/* Right half of decoded 8-bit CW */
		uint8_t r[4];

		/* Key expansion */
		_expand(C, k, ek);

		/* Plain text expansion */
		_expand(E, cw, ecw);

		/* Main */
		for(j = 31, c = 0; c < 8; c++)
		{
			uint8_t x, sb, m;
			uint8_t b, l; //int

			/* XOR key with CW */
			x = (ek[c] ^ ecw[c]) & 0x3F;

			/* S-box selection */
			sb = pgm_read_byte(&S[x >> 1 | (0x20 * (8 - c) & 0xFF)]);
			if(x & 1) sb = sb << 4 & 0xF0;

			/* Permutation */
			for(l = 0; l < 4; l++, j--)
			{
				b = pgm_read_byte(&P[j]) & 0x03;
				m = 1 << ((pgm_read_byte(&P[j]) >> 4) & 0x07);
				r[b] = sb & 0x80 ? r[b] & (m ^ 0xFF) : r[b] | m;
				sb <<=1;
			}
		}
        uint8_t l;
		/* XOR to create r then rotate left/right halves of CW */
		for(l = 0; l < 4; l++)
		{
			 r[l + 0] ^= cw[l + 4];
			cw[l + 4]  = cw[l + 0];
			cw[l + 0]  =  r[l + 0];
		}

		/* Rotate key */
		_key_rotate(i, k);
	}
}

uint16_t _get_syster_cw(uint8_t ecm[16], uint8_t k64[8],uint8_t *out)
{
	uint8_t round, i;
	uint16_t date;
	uint8_t buffer1[8], cw[8], pcw[8];


    /* Run twice - one for each half of the 16-byte encrypted control word */
	for(round = 0; round < 2; round++)
	{
		unsigned char k56[8], buffer2[8];
        //uint8_t audi = *aud;

		/* Convert 64-bit key to 56-bit key */
		_permute(k64, k56, kp);
		k56[0] = k56[4] << 4;

		/* Initial CW permutation */
		_permute(ecm + round * 8, pcw, ip);

		/* Call main DES function */
		_syster_des_f(k56, pcw);

		/* Final permutation of CW */
		_permute(pcw, buffer2, fp);

		if(round == 0)memcpy(&out[8],&buffer2[6],1);

        memcpy(&date,buffer2,2);

        if(date == 0xFFFF){
            memcpy(&date,buffer2+2,2);
        }

		/* Copy each half of decoded CW into output buffer2 */
		memcpy(buffer1 + round * 4, buffer2 + round * 4, 4);
	}

	/* Create final decoded control word */
	for(i = 0; i < 4; i++)
	{
		cw[i] = buffer1[i + 4] & (i == 3 ? 0x7F : 0xFF);
	}
	cw[4] = buffer1[0] << 1 | (buffer1[7] >> 7 & 1);
	cw[5] = buffer1[1] << 1 | (buffer1[0] >> 7 & 1);
	cw[6] = buffer1[2] << 1 | (buffer1[1] >> 7 & 1);
	cw[7] = ((buffer1[3] << 1 & 0x1F) | (buffer1[2] >> 7 & 1));

	memcpy(out,cw,8);
	return date;
}
