/* AVR-based Nagravision Syster card/key firmware for hacktv             */
/*=======================================================================*/
/* Copyright 2020 Marco Wabbel <marco@familie-wabbel.de>                 */
/* Copyright 2019 Philip Heron <phil@sanslogic.co.uk> (cmd-handling)     */
/* Thanks to Philip Heron and Alexander James for some codings           */
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

/* Hardware setup:
 *
 * F_CPU is provided by the decoder at 26.625 MHz / 7.
 * PB6 is I/O, 9-bit software serial.
 * Timer1 is used to drive I/O on PB6. ICP is used for Interrupt driven RX
 * A FiFo is used to receive and Answer IOs during DES-Decryption
*/

#include "config.h"
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>

#include "uart.h"
#include <string.h>
#include <avr/eeprom.h>
#include "systerdes.h"

/* Some helpers */
uint8_t check = 0;
uint8_t _cryptmode EEMEM = 0;
uint8_t _atrindex EEMEM = 0x10;
uint16_t _maxdate = 0;
uint16_t _mindate = 0;


/* PROGMEM VALUES */
const uint8_t _response_0200_prde[] PROGMEM = {
	0xA0,0x02,0x1C,0x38,0x14,0x05,0xFF,0x14,0xE1,0xE5,0x00
};

const uint8_t _response_0200_cpfr[] PROGMEM = {
	0xA0,0x02,0x18,0x38,0x12,0x00,0xFF,0x14,0x80,0x83,0x00
};

const uint8_t _response_0200_cppl[] PROGMEM = {
	0xA0,0x02,0x1C,0xE0,0x0C,0x01,0xFF,0x14,0xE1,0xE5,0x00
};

const uint8_t _response_5700[] PROGMEM = {
	0x01,0x02,0x4F,0x53,0x30,0x40,0x74,0x72,0x4B,0x1D,0x00
};

const uint8_t _response_5701[] PROGMEM = {
	0x01,0x02,0x00,0x40,0x00,0x00,0x74,0x72,0x4B,0x1D,0x00
};

const uint8_t _response_5702[] PROGMEM = {
	0x01,0x02,0x4F,0x53,0x30,0x42,0x74,0x72,0x4B,0x1D,0x00
};


/* EEPROM VALUES */
/* channels for cable-terminal */
uint8_t _response_0201[] EEMEM = {
	0x01,0x02,0x19,0x01,0x1A,0x01,0x1B,0x01,0x1C,0x01,0x00
};

/* subscription info */
uint8_t _response_5F000000[] EEMEM = {
    0x00,0x01,0xFF,0xFF,0x61,0x6B,0xDF,0xBB,0x21,0x80
};

uint8_t _response_5F000100[] EEMEM = {
    0x00,0x01,0xFF,0xFF,0x60,0x6A,0xDF,0xC1,0x21,0xBC
};

/* KEYS */
uint32_t _xtea_key[2][4] EEMEM = {
    {0x00112233,0x44556677,0x8899AABB,0xCCDDEEFF},
    {0xd5784071,0x48909110,0x01260c7a,0xd5579e9d},
};

uint8_t _deskey[8][8] EEMEM = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34}, // Key 0 premiere
    {0x00, 0xE2, 0x51, 0x6D, 0x15, 0x97, 0x51, 0x55}, // Key 1 premiere
    {0x00, 0xAE, 0x52, 0x90, 0x49, 0xF1, 0xF1, 0xBB}, // KEY 0 C+ France
    {0x00, 0xE9, 0xEB, 0xB3, 0xA6, 0xDB, 0x3C, 0x87}, // KEY 1 C+ France
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Key 0 C+ Poland
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Key 1 C+ Poland
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Key 0 reserved
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Key 1 reserved
};

uint8_t _des11key[] EEMEM = {
    0xC4, 0xA5, 0xA8, 0x18, 0x74, 0x93, 0xC7, 0x65
};

/* Response buffer */
static uint16_t _ob[16];
static int _ob_x = 0;
static int _ob_len = 0;
static uint8_t cryptmode;
static uint8_t keyindex;
static uint8_t atrindex;
static uint8_t key64[8];

void _update_channels(void){
    int i;
    for(i=0;i<8;i++){
        eeprom_update_byte(&_response_0201[i+2],(_ob[i]&0xff));
    }
}

void _update_key(uint8_t ki){
    int i;
    for(i=0;i<8;i++){
        eeprom_update_byte(&_deskey[ki][i],(_ob[i]&0xff));
    }
}

void _rand_seed_des(uint8_t ki,uint8_t aud){

    enable_rx(); /* Answer FF FF during decryption */
    uint16_t checkdate = 0;

    if(aud == 0x11){
        eeprom_read_block(key64,_des11key,8);
    } else {
        eeprom_read_block(key64,_deskey[ki+((atrindex & 0xf) * 2)],8);
    }


    uint8_t ib[16],i;
    uint8_t ob[9];
    for(i=0;i<16;i++)ib[i] = _ob[i];
    checkdate = _get_syster_cw(ib,key64,ob);
    for(i=0;i<8;i++)_ob[i+1] = ob[i];
    if((atrindex & 0xF0) == 0x10 && aud != 0x11){
        if(checkdate >= _mindate && checkdate <= _maxdate && aud == ob[8] ){
            check = 0;
        } else {
            check = 1;
        };
    };
}


void _rand_seed_xtea(uint8_t ki)
{
	int i;
	uint32_t v0 = 0;
	uint32_t s0 = 0;
	uint32_t v1 = 0;
	uint32_t s1 = 0;
	uint32_t sum = 0;
	uint32_t delta = 0x9E3779B9;

    uint32_t xtea_key[4];
    for(i=0;i<4;i++){
        xtea_key[i] = eeprom_read_dword(&_xtea_key[ki % 2][i]);
    }
     for(i=3;i>-1;i--){
        v1 <<= 8;
        v1 |= (_ob[i] & 0xff);
        s1 <<= 8;
        s1 |= (_ob[i+8] & 0xff);
        v0 <<= 8;
        v0 |= (_ob[i+4] &0xff); //8 12
        s0 <<= 8;
        s0 |= (_ob[i+12] & 0xff);
    }
if(cryptmode == 2){
	for (i = 0; i < 32;i++)
	{
		v0 += (((v1 << 4)^(v1 >> 5)) + v1)^(sum + xtea_key[sum & 3]);
		sum += delta;
		v1 += (((v0 << 4)^(v0>>5))+v0)^(sum + xtea_key[(sum>>11) & 3]);
		if(i == 7)
		{
            /* SIG-CHECK */
            if((v0 == s0) && (v1 == s1)){
                check = 0;
            }else{
                check = 1;
                break;
            }
		}
	}
}
    for(i=0;i<4;i++){
        _ob[i+1] = 0 | ((v1>>(i*8)) & 0xFF);
        _ob[i+5] = 0 | ((v0>>(i*8)) & 0xFF);
    }
}



void _io_response_ee(const uint8_t *data)
{
	int i;
	for(i = 1; i < 11; i++)
	{
		_ob[(_ob_x + _ob_len) & 0x0F] = eeprom_read_byte(&data[i]);
		_ob_len++;
	}
	_ob[_ob_x] |= 0x100;
	_ob[(_ob_x + 9) & 0x0F] |= 0x100;

	io_write(0x100 | eeprom_read_byte(&data[0]));
}

void _io_response_pgm(const uint8_t *data)
{
	int i;
	for(i = 1; i < 11; i++)
	{
		_ob[(_ob_x + _ob_len) & 0x0F] = pgm_read_byte(&data[i]);
		_ob_len++;
	}
	_ob[_ob_x] |= 0x100;
	_ob[(_ob_x + 9) & 0x0F] |= 0x100;

	io_write(0x100 | pgm_read_byte(&data[0]));
}

void _command(uint16_t cmd)
{
	uint16_t c;
	int i;

	switch(cmd)
	{
    case 0x0100:
    case 0x0101:
                io_write(0x101);

                for(i = 0; i < 8; i += 2)
                {
                    _ob[i + 0] = io_read();
                    _ob[i + 1] = io_read();
                    io_write(0x101);
                }
                _update_channels();
                io_read();
                io_read();
                io_write(0x100);

                break;
	case 0x0200:
                switch(atrindex & 0x0F){
                    case 0x00:
                        _io_response_pgm(_response_0200_prde); break;
                    case 0x01:
                        _io_response_pgm(_response_0200_cpfr); break;
                    case 0x02:
                        _io_response_pgm(_response_0200_cppl); break;
                } break;
	case 0x0201: _io_response_ee(_response_0201); break;
	case 0x0400:
    case 0x0401:
    case 0x0402:
                io_write(0x1FF);

                cryptmode = cmd & 0xFF;
                eeprom_update_byte(&_cryptmode,cryptmode); break;
	case 0x1400:
    case 0x1401:
    case 0x1402:
	case 0x1410:
    case 0x1411:
    case 0x1412:
                io_write(0x1FF);

                atrindex = cmd & 0xFF;
                eeprom_update_byte(&_atrindex,atrindex); break;
    case 0x2400:
    case 0x2401:
    case 0x2402:
    case 0x2403:
    case 0x2404:
    case 0x2405:
    case 0x2406:
    case 0x2407:
    case 0x2408:
    case 0x2409:
    case 0x240A:
    case 0x240B:
    case 0x240C:
    case 0x240D:
    case 0x240E:
    case 0x240F:
                io_write(0x1FF);

                keyindex = cmd & 0x0F;
                		for(i = 0; i < 8; i += 2){
                            _ob[i + 0] = io_read();
                            _ob[i + 1] = io_read();
                            io_write(0x124);

                        }
                _update_key(keyindex);break;
	case 0x5700: _io_response_pgm(_response_5700); break;
	case 0x5701: _io_response_pgm(_response_5701); break;
	case 0x5702: _io_response_pgm(_response_5702); break;
    case 0x5f00:
                io_write(0x101);

                c = io_read();
                io_read();
                switch(c){
                    case 0x00:
                        io_write(0x101);

                        _ob_x = 0;
                        _ob_len = 0;
                        for(i=1;i<10;i++){
                            _ob[i] = eeprom_read_byte(_response_5F000000+i);
                        }
                        _ob[0] = 0x102;
                        _ob[10] = 0x100;
                        _ob_x = 0;
                        _ob_len = 11;
                        break;

                    case 0x01:
                        io_write(0x101);

                        _ob_x = 0;
                        _ob_len = 0;

                        for(i=1;i<10;i++){
                            _ob[i] = eeprom_read_byte(_response_5F000100+i);
                        }
                        _ob[0] = 0x102;
                        _ob[10] = 0x100;
                        _ob_x = 0;
                        _ob_len = 11;
                        break;

                    case 0x02:
                        io_write(0x101);

                        io_read();
                        io_read();
                        io_write(0x14A);

                        break;
                    case 0x03:
                        io_write(0x101);

                        io_read();
                        io_read();
                        io_write(0x14a);

                        break;
                }
                break;
    case 0x5E00:
    case 0x5E01:
    case 0x5E02:
    case 0x5F01:
    case 0x5F02:
                io_write(0x101);

                io_read();
                io_read();
                io_write(0x101);

                io_read();
                io_read();
                io_write(0x14A);

                break;
	case 0x0500:
	case 0x0501:
                io_write(0x101);

                for(i = 0; i < 32; i++)
                {
                    io_read();
                    io_read();
                    io_write(0x101);

                }
                break;
	case 0x0600:
    case 0x0620:
    case 0x0601:
    case 0x0621:
    case 0x0602:
    case 0x0622:
    case 0x0611:
                io_write(0x101);

                keyindex = (cmd & 0xF0) >> 5;

                _ob_x = 0;
                _ob_len = 0;

                for(i = 0; i < 16; i += 2)
                {
                    _ob[i + 0] = io_read();
                    _ob[i + 1] = io_read();
                    io_write(0x101);
                }

                if(cryptmode == 0){
                    _rand_seed_des(keyindex,cmd & 0xFF);
                } else {
                    _rand_seed_xtea(keyindex);
                }
                if(check == 0){
                    _ob[0] = 0x106;
                    _ob[9] = 0x102;
                    _ob_x = 0;
                    _ob_len = 10;
                } else {
                    _ob[0] = 0x10A;
                    _ob_x = 0;
                    _ob_len = 1;
                } break;
	case 0xFFFF:
                c = 0x101;
                if(_ob_len > 0)
                {
                    c = _ob[_ob_x];
                    _ob_x++;
                    _ob_len--;
                if(_ob_x == 16)
                {
                    _ob_x = 0;
                }
                }
                io_write(c);
                break;
    default:
            io_write(0x101);

            break;
	}

}

int main(void)
{

    uint16_t a, b;

	/* Enable interrupts */
	sei();

    io_init();
    enable_rx();

	a = b = 0;

    cryptmode = eeprom_read_byte(&_cryptmode);
    atrindex = eeprom_read_byte(&_atrindex);
	eeprom_read_block(&_mindate,&_response_5F000000[8],2);
	eeprom_read_block(&_maxdate,&_response_5F000100[6],2);



	while(1)
	{

		a = b;
		b = io_read();

		if((a & 0x100) == 0x100 &&
		   (b & 0x100) == 0x000)
		{
			_command((a << 8) | b);
		}
	}

	return(0);
}
