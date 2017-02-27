/* entropium.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2006-2015 Daniel Otte (bg@nerilex.org)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * \file    entropium.c
 * \author  Tobias Schramm
 * \email   cryptolib@t-sys.eu
 * \date    2017 - 02 - 27
 * \license	GPLv3 or later
 * \brief	This file contains an implementaition of a pseudo-random-number generator.
 * 
 * Extension 1:
 * 	md5 is used because sha 1 and sha 256 asm implementations are broken
 *
  \verbatim
                       ################################################################################################
                       #                                                                                              #
                       #         +---------------------------+                                                        #
                       #         |                           |                                                        #
                       #         V                           |                                                        #
                       #      (concat)                       |                                                        #
   +---------------+   #    o---------o             (xor)+---------+      o---------o        o----o     o---------o   #    +--------------+
   | entropy Block | -----> |   md5   | --(offset)-<     | rndCore | ---> |   md5   | --+----| +1 |---> |   md5   | -----> | random Block |
   +---------------+   #    o---------o             (xor)+---------+      o---------o   |    o----o     o---------o   #    +--------------+
                       #                                 (xor) (xor)                    |                             #
                       #                                   ^     ^                      |                             #
                       #                                    \   /                       |                             #
                       #                                   (offset)---------------------+                             #
                       #                                                                                              #
                       ################################################################################################
  \endverbatim
 */

#include <stdint.h>
#include <string.h>
#include "md5.h"
#include "entropium-md5.h"

/**
 * \brief secret entropy pool. 
 * This is the core of the random which is generated
 */
uint32_t rndCore[ENTROPIUM_RANDOMBLOCK_SIZE]; 

/*************************************************************************/

/* idea is: hash the message and add it via xor to rndCore
 *
 * length in bits 
 * 
 * we simply first "hash" rndCore, then entropy.
 */
void entropium_addEntropy(unsigned length_b, const void *data){
	static uint8_t offset = 0; /* selects if higher or lower half gets updated */
	md5_ctx_t s;
	md5_init(&s);
	md5_nextBlock(&s, rndCore);
	while (length_b >= MD5_BLOCK_BITS){
		md5_nextBlock(&s, data);
		data = (uint8_t*)data + MD5_BLOCK_BYTES;
		length_b -= MD5_BLOCK_BITS;	
	}
	md5_lastBlock(&s, data, length_b);
	uint8_t i;
	for (i=0; i < MD5_BLOCK_BYTES / 4 / 4; ++i){
		rndCore[i + offset] ^= s.a[i];
	}
	offset += ENTROPIUM_RANDOMBLOCK_SIZE / 4;
	offset %= ENTROPIUM_RANDOMBLOCK_SIZE;
}

/*************************************************************************/

void entropium_getRandomBlock(void *b){
	static uint8_t offset = ENTROPIUM_RANDOMBLOCK_SIZE / 2;
	md5_ctx_t s;
	
	md5_init(&s);
	md5_lastBlock(&s, rndCore, ENTROPIUM_RANDOMBLOCK_SIZE * 8 * 4); /* remeber the byte order! */
	uint8_t i;
	for (i=0; i < MD5_BLOCK_BYTES / 4 / 4; i++){
		rndCore[i + offset] ^= s.a[i];
	}
	offset += ENTROPIUM_RANDOMBLOCK_SIZE / 4;
	offset %= ENTROPIUM_RANDOMBLOCK_SIZE;
	memcpy(b, s.a, MD5_HASH_BYTES); /* back up first hash in b */
	((uint8_t*)b)[*((uint8_t*)b) & (ENTROPIUM_RANDOMBLOCK_SIZE - 1)]++; 	/* the important increment step */
	md5_init(&s);
	md5_lastBlock(&s, b, ENTROPIUM_RANDOMBLOCK_SIZE * 8 * 4 / 2);
	memcpy(b, s.a, MD5_HASH_BYTES);
}

/*************************************************************************/

uint8_t entropium_getRandomByte(void){
	static uint8_t block[ENTROPIUM_RANDOMBLOCK_SIZE];
	static uint8_t i = ENTROPIUM_RANDOMBLOCK_SIZE;
	
	if (i == ENTROPIUM_RANDOMBLOCK_SIZE){
		entropium_getRandomBlock((void*)block);
		i=0;
	}	
	return block[i++];
}

void entropium_fillBlockRandom(void *block, unsigned length_B){
	while(length_B>ENTROPIUM_RANDOMBLOCK_SIZE){
		entropium_getRandomBlock(block);
		block = (uint8_t*)block + ENTROPIUM_RANDOMBLOCK_SIZE;
		length_B -= ENTROPIUM_RANDOMBLOCK_SIZE;
	}
	while(length_B){
		*((uint8_t*)block) = entropium_getRandomByte();
		block= (uint8_t*)block +1; --length_B;
	}
}
 
 
