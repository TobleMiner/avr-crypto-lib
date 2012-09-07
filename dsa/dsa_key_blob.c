/* dsa_key_blob.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2010 Daniel Otte (daniel.otte@rub.de)

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

#include <stdlib.h>
#include <stdint.h>
#include <avr/pgmspace.h>
#include "cli.h"
#include "dsa.h"
#include "bigint.h"


#define DSA_KEY_BLOB_SIZE 1024

#if DSA_KEY_BLOB_SIZE == 512

#define PRIV_LEN_B (20)
#define PUB_LEN_B  (8*8)
#define P_LEN_B (8*8)
#define Q_LEN_B (20)
#define G_LEN_B (8*8)
#define ALL_LEN_B (PRIV_LEN_B+PUB_LEN_B+P_LEN_B+Q_LEN_B+G_LEN_B)


static const uint8_t dsa_key_blob[] PROGMEM = {

//	priv:
	0xac, 0xe6, 0xef, 0x99, 0x08, 0xe8, 0x5f, 0xc8,
	0xc7, 0x51, 0x97, 0x99, 0xf4, 0xd3, 0x00, 0x0f,
	0x49, 0x72, 0xee, 0x46,
//	pub:
	0x18, 0x02, 0x53, 0x09, 0x61, 0xad, 0x0b, 0x9d,
	0x44, 0x80, 0x8d, 0xb4, 0x52, 0xdc, 0xb5, 0xf2,
	0x11, 0x20, 0x41, 0xc7, 0xd9, 0x7c, 0x7c, 0x6c,
	0xa0, 0x9e, 0xca, 0x0d, 0xff, 0x28, 0x3c, 0x64,
	0xfa, 0x92, 0xbb, 0x2c, 0xe9, 0x9b, 0x10, 0x94,
	0xa5, 0x8d, 0x03, 0x50, 0xa5, 0x59, 0xd4, 0x3f,
	0x57, 0x78, 0x8d, 0xcf, 0x0a, 0x99, 0x5d, 0xa3,
	0x2e, 0x80, 0xfa, 0x99, 0x44, 0x73, 0x6d, 0x9a,
//	P:
	0x9f, 0x2d, 0xc8, 0x3c, 0x34, 0xf9, 0xa1, 0xbc,
	0x6a, 0xa7, 0x49, 0x17, 0xd3, 0x82, 0xa2, 0xe2,
	0x25, 0x31, 0xc4, 0x3d, 0x1a, 0x3f, 0x0f, 0x8a,
	0x8b, 0x84, 0x3c, 0x6c, 0x9c, 0xdd, 0x42, 0xd9,
	0x1a, 0x22, 0xf2, 0x55, 0x98, 0xee, 0x7d, 0x98,
	0x9c, 0x9a, 0x91, 0x42, 0x5f, 0x4f, 0xa8, 0x32,
	0xa0, 0xb0, 0x0f, 0x79, 0xe2, 0x76, 0x08, 0x78,
	0x6e, 0xba, 0xf7, 0x74, 0x43, 0x4a, 0xf2, 0xdf,
//	Q:
	0xdb, 0x30, 0x69, 0xe6, 0x59, 0x77, 0xee, 0x38,
	0xea, 0xf7, 0xcc, 0x18, 0x83, 0xcf, 0xb4, 0x21,
	0xbc, 0xcf, 0x9a, 0x77,
//	G:
	0x73, 0x90, 0x27, 0x68, 0xe7, 0xe9, 0x3a, 0x45,
	0x6f, 0x7f, 0x95, 0xca, 0x9b, 0xfd, 0x33, 0x75,
	0x75, 0xff, 0x0f, 0xe7, 0x69, 0xfd, 0xb7, 0x07,
	0x0f, 0x6c, 0x3a, 0xec, 0x47, 0x82, 0x78, 0xb2,
	0xb3, 0x0b, 0x7f, 0x11, 0x9d, 0x34, 0x3e, 0xff,
	0xb8, 0x09, 0x42, 0x82, 0x81, 0x21, 0xad, 0x2b,
	0x51, 0x20, 0xec, 0x9e, 0xf8, 0x15, 0xaa, 0x3d,
	0x5f, 0x29, 0x2d, 0xb5, 0xc5, 0x64, 0x53, 0x2d
};

#endif

#if DSA_KEY_BLOB_SIZE == 1024

#define PRIV_LEN_B (20)
#define PUB_LEN_B  (16*8)
#define P_LEN_B (16*8)
#define Q_LEN_B (20)
#define G_LEN_B (16*8)
#define ALL_LEN_B (PRIV_LEN_B+PUB_LEN_B+P_LEN_B+Q_LEN_B+G_LEN_B)

static const uint8_t dsa_key_blob[] PROGMEM = {
	// priv:
	0x03, 0xad, 0x17, 0x81, 0x0f, 0x70, 0x7f, 0x89,
	0xa2, 0x0a, 0x70, 0x1c, 0x3b, 0x24, 0xff, 0xd2,
	0x39, 0x93, 0xd7, 0x8d,
	// pub:
	0x42, 0x1c, 0xb2, 0x03, 0xe5, 0xc6, 0x69, 0x81,
	0x1e, 0x35, 0x85, 0x86, 0xd7, 0x94, 0xd2, 0x1f,
	0x77, 0x05, 0x2f, 0xcc, 0xa5, 0x69, 0x46, 0x8f,
	0xe1, 0x9f, 0x82, 0xf6, 0x24, 0x2c, 0x64, 0x1b,
	0x29, 0x63, 0xd5, 0xb3, 0x32, 0xdc, 0xd9, 0x5a,
	0x4e, 0x92, 0xd9, 0x69, 0xcc, 0x51, 0x81, 0xc2,
	0xa3, 0x7e, 0xd7, 0xf8, 0x72, 0x1f, 0x8d, 0xd4,
	0xe8, 0x59, 0xb0, 0xaa, 0xdd, 0xa0, 0x73, 0xe6,
	0xc4, 0x50, 0x7f, 0x4c, 0x7c, 0xde, 0x35, 0x27,
	0x49, 0x36, 0x23, 0x36, 0xe4, 0x90, 0x54, 0x24,
	0x45, 0x99, 0xa3, 0x10, 0xc3, 0x59, 0x2f, 0x61,
	0xff, 0x75, 0xf0, 0x51, 0x1d, 0xa0, 0x8f, 0x69,
	0xc1, 0x1e, 0x3e, 0x65, 0xaf, 0x82, 0x9e, 0xa9,
	0x91, 0x17, 0x04, 0x7c, 0x56, 0xd1, 0x68, 0x8a,
	0x4b, 0xc9, 0x48, 0x92, 0xaf, 0x72, 0xca, 0xbf,
	0xf2, 0x2b, 0x9e, 0x42, 0x92, 0x46, 0x19, 0x64,
	// P:
	0x97, 0x40, 0xda, 0x05, 0x19, 0x77, 0xb7, 0x17,
	0x4b, 0x7d, 0xc0, 0x5b, 0x81, 0xdd, 0xcc, 0x0b,
	0x86, 0xe0, 0x3c, 0x4d, 0xab, 0x3d, 0x43, 0xe4,
	0xe3, 0x5f, 0xf3, 0x56, 0xcd, 0x5c, 0xf2, 0x85,
	0x00, 0x45, 0x3c, 0xba, 0xf0, 0x56, 0xb3, 0x8b,
	0x29, 0xc3, 0x55, 0x7b, 0xb6, 0xfb, 0x68, 0xca,
	0x35, 0xe5, 0x0e, 0x46, 0xd6, 0xff, 0xc9, 0xbd,
	0x08, 0x71, 0x65, 0x3b, 0xf7, 0xab, 0xb1, 0x96,
	0x9b, 0x70, 0xdc, 0x8e, 0xf3, 0x02, 0xa4, 0x0f,
	0xc6, 0xcd, 0x70, 0xe5, 0xeb, 0xd3, 0x07, 0xb5,
	0x7d, 0x40, 0x8c, 0xfd, 0x33, 0x45, 0x8f, 0x9c,
	0x7f, 0xa1, 0x69, 0xcb, 0xe6, 0x73, 0x1d, 0x37,
	0xc7, 0x5f, 0x18, 0x57, 0x38, 0x96, 0x46, 0x24,
	0xad, 0xa6, 0x59, 0x3d, 0x7a, 0x74, 0x6e, 0x88,
	0x57, 0x18, 0x86, 0x7b, 0x07, 0x79, 0x52, 0xdd,
	0xbc, 0xa7, 0x40, 0x88, 0xa6, 0x66, 0x50, 0x49,
	// Q:
	0xb4, 0x6d, 0x89, 0x7a, 0x72, 0xdb, 0x8c, 0x92,
	0x60, 0xf9, 0x95, 0x47, 0x81, 0x57, 0xe8, 0x6b,
	0xb4, 0xf9, 0xde, 0x51,
	// G:
	0x76, 0x1e, 0x1b, 0xd2, 0x5c, 0x5f, 0x92, 0x96,
	0x42, 0x18, 0xba, 0x8d, 0xe1, 0x24, 0x12, 0x24,
	0x6f, 0x3f, 0xb8, 0x05, 0xf9, 0x72, 0x74, 0xfa,
	0xef, 0xc3, 0x1e, 0xd5, 0xa5, 0x93, 0x28, 0x07,
	0xc0, 0x7b, 0x47, 0xef, 0x15, 0x13, 0x68, 0x18,
	0xfb, 0x0d, 0x69, 0xea, 0xcc, 0x5a, 0x43, 0x08,
	0x75, 0xec, 0xe4, 0x5e, 0x8e, 0xa9, 0x61, 0xe1,
	0xcd, 0x27, 0x8c, 0x55, 0xc9, 0x42, 0x11, 0x11,
	0x7f, 0x20, 0x4d, 0x70, 0x34, 0x49, 0x00, 0x8c,
	0x79, 0x95, 0x79, 0x0b, 0xfd, 0x8d, 0xda, 0xe3,
	0x0c, 0x27, 0x7a, 0x35, 0xe5, 0x35, 0xc9, 0x73,
	0x31, 0xaa, 0xed, 0xbe, 0x81, 0x89, 0x67, 0x06,
	0xf6, 0x97, 0x0d, 0x44, 0x07, 0xac, 0x09, 0xac,
	0x44, 0xf3, 0xc6, 0x8b, 0x30, 0x4c, 0x76, 0x0b,
	0x55, 0x74, 0x10, 0x06, 0xda, 0xd4, 0x3d, 0x96,
	0x7e, 0xc3, 0xf8, 0x22, 0x9c, 0x71, 0x1d, 0x9c
};
#endif

#if DSA_KEY_BLOB_2048

#define PRIV_LEN_B (20)
#define PUB_LEN_B  (32*8)
#define P_LEN_B (32*8)
#define Q_LEN_B (20)
#define G_LEN_B (32*8)
#define ALL_LEN_B (PRIV_LEN_B+PUB_LEN_B+P_LEN_B+Q_LEN_B+G_LEN_B)

static const uint8_t dsa_key_blob[] PROGMEM = {
/* priv: */
	0x1d, 0xe4, 0x81, 0x02, 0x52, 0x6b, 0x2b, 0x0e,
	0x98, 0x08, 0xc8, 0xb9, 0x81, 0x40, 0xd1, 0x1e,
	0x86, 0x69, 0x0d, 0xa9,
/* pub: */
	0x70, 0xc4, 0x44, 0x28, 0x91, 0x77, 0x2b, 0x09,
	0xde, 0xe8, 0x66, 0x0b, 0xa5, 0xc8, 0x05, 0xb4,
	0x0a, 0x2d, 0x4f, 0x45, 0x8e, 0x0c, 0x8c, 0x38,
	0x61, 0xf3, 0x77, 0x05, 0x64, 0xf7, 0xe6, 0xe9,
	0x0b, 0x1f, 0x9b, 0x9f, 0x1f, 0xa1, 0x7e, 0x8f,
	0x5b, 0x14, 0x70, 0x1d, 0x4d, 0x1c, 0xdc, 0x9d,
	0xe0, 0x0a, 0xc4, 0x7b, 0x70, 0xfd, 0xef, 0xe6,
	0x20, 0x2d, 0x17, 0x13, 0xd7, 0x1c, 0xc0, 0xbb,
	0x5b, 0xce, 0x84, 0x6a, 0xa5, 0x4e, 0x27, 0x1c,
	0x9e, 0xaa, 0xb2, 0xdc, 0xc1, 0xec, 0x74, 0x93,
	0x67, 0xdb, 0xe1, 0xaa, 0x5a, 0x86, 0x1d, 0x8a,
	0xa9, 0x28, 0x7e, 0xfc, 0xd5, 0x72, 0x94, 0x6c,
	0x1d, 0x71, 0x85, 0x92, 0xa7, 0x6e, 0x84, 0x4f,
	0x27, 0xf3, 0x7e, 0x04, 0x7d, 0xf2, 0x7c, 0x07,
	0xa0, 0x7d, 0x02, 0x7c, 0x30, 0x70, 0xb5, 0x87,
	0xc3, 0xf0, 0xc2, 0x0c, 0xdb, 0x26, 0x72, 0x33,
	0x20, 0xca, 0xf0, 0x8b, 0x05, 0x20, 0x70, 0x98,
	0x65, 0x03, 0xd7, 0xd4, 0x47, 0xf0, 0xb2, 0x6e,
	0x2a, 0xbe, 0xcc, 0x83, 0x0d, 0xab, 0x60, 0x61,
	0x26, 0x7b, 0xaf, 0xae, 0x18, 0x9e, 0x20, 0xeb,
	0x12, 0x31, 0x18, 0x2e, 0x73, 0xca, 0xd4, 0x5e,
	0x66, 0x74, 0x61, 0x07, 0x9b, 0x20, 0x68, 0x12,
	0x88, 0xb1, 0xc5, 0x0f, 0x85, 0x9b, 0x45, 0x40,
	0x7d, 0x76, 0x62, 0x73, 0xba, 0x41, 0x7b, 0xaf,
	0xc7, 0xb9, 0x19, 0x7a, 0xd0, 0x55, 0xe6, 0xfd,
	0xb5, 0xb9, 0xc4, 0x1b, 0x22, 0x47, 0x8f, 0x7b,
	0xd7, 0x75, 0xe8, 0x7f, 0x01, 0xa2, 0x9b, 0x79,
	0xde, 0xea, 0x55, 0x3c, 0x61, 0x4d, 0xcd, 0xce,
	0x89, 0x8c, 0x76, 0x62, 0x12, 0x4d, 0xd4, 0x47,
	0x03, 0x0e, 0xe8, 0xe2, 0xb8, 0xda, 0xca, 0x20,
	0xb3, 0x64, 0xb6, 0x07, 0x06, 0x1b, 0xcb, 0x91,
	0x51, 0x2c, 0x2e, 0xfa, 0xe1, 0xee, 0x1e, 0x78,
/* P: */
	0x8d, 0x09, 0x00, 0x56, 0x63, 0x39, 0x42, 0x8d,
	0x15, 0xd5, 0x1d, 0x86, 0x10, 0xde, 0xc7, 0xf4,
	0x07, 0xe5, 0x81, 0xbe, 0x67, 0xee, 0xc5, 0x33,
	0xd3, 0x41, 0x1b, 0xba, 0xd8, 0xa6, 0x61, 0x49,
	0x2d, 0x66, 0xcf, 0x60, 0x9f, 0x52, 0x60, 0x6e,
	0x0a, 0x16, 0xdc, 0x0b, 0x24, 0x1b, 0x62, 0x32,
	0xc4, 0xab, 0x52, 0x17, 0xbf, 0xc5, 0xa2, 0x2a,
	0xa4, 0x5e, 0x8c, 0xff, 0x97, 0x45, 0x51, 0xd9,
	0xc3, 0xf2, 0x32, 0x4a, 0xb9, 0x08, 0xc1, 0x6a,
	0x7b, 0x82, 0x93, 0x2a, 0x60, 0x29, 0x55, 0x1a,
	0x36, 0x1f, 0x05, 0x4f, 0xf1, 0x43, 0x12, 0xb2,
	0x73, 0x4e, 0xf6, 0x37, 0x65, 0x3d, 0x0b, 0x70,
	0x08, 0xc7, 0x34, 0x0b, 0x4d, 0xc9, 0x08, 0x70,
	0xaf, 0x4b, 0x95, 0x0b, 0x7c, 0x9f, 0xcf, 0xfc,
	0x57, 0x94, 0x47, 0x6d, 0xd1, 0xaf, 0xc6, 0x52,
	0xd9, 0xe2, 0x05, 0xce, 0xb2, 0xb8, 0x91, 0x6f,
	0x5a, 0x77, 0x6b, 0x1b, 0xff, 0x97, 0x8c, 0x5e,
	0x33, 0xfc, 0x80, 0x29, 0xdf, 0x83, 0x91, 0x0c,
	0x28, 0x1b, 0x00, 0xb4, 0xc9, 0x3e, 0xb7, 0x67,
	0xca, 0xab, 0x63, 0xd4, 0x48, 0xfe, 0xd2, 0xfd,
	0x65, 0x57, 0x33, 0x25, 0xbd, 0xf1, 0xa5, 0x51,
	0x51, 0x50, 0xf6, 0xcf, 0xfa, 0x0d, 0x67, 0x4e,
	0x90, 0x08, 0x87, 0x34, 0xf6, 0x33, 0xc9, 0x58,
	0xb1, 0x87, 0xf8, 0x5d, 0x73, 0x80, 0xde, 0x51,
	0xcd, 0x17, 0x70, 0x3e, 0xa4, 0xa8, 0x4f, 0xda,
	0xcd, 0xa2, 0x66, 0x0f, 0x95, 0xa7, 0xc6, 0xf7,
	0x12, 0x2e, 0x27, 0x94, 0xa9, 0x26, 0x1b, 0x25,
	0x16, 0x18, 0x99, 0x3b, 0x32, 0xaf, 0x71, 0x13,
	0x35, 0xda, 0xb8, 0x71, 0x5b, 0x50, 0x7c, 0x7a,
	0x9d, 0xcc, 0x0d, 0x95, 0xef, 0x6f, 0x64, 0x3c,
	0x28, 0x4b, 0x15, 0xe9, 0xd4, 0xad, 0xcc, 0x56,
	0xcb, 0x24, 0xf9, 0x61, 0x79, 0xd7, 0x56, 0xd3,
/* Q: */
	0xf7, 0xdf, 0x85, 0xf5, 0x63, 0x36, 0x63, 0x71,
	0x74, 0x34, 0x98, 0x19, 0xff, 0x79, 0xf2, 0xe2,
	0x15, 0x75, 0x3c, 0x95,
/* G: */
	0x0c, 0xf6, 0x8b, 0x1a, 0xbe, 0x66, 0x84, 0x98,
	0xae, 0xcb, 0xb0, 0xd9, 0x75, 0x75, 0x32, 0x4b,
	0xa3, 0xf2, 0x28, 0xa6, 0x6d, 0x13, 0xf2, 0xf3,
	0xfd, 0x93, 0x91, 0xb1, 0x21, 0x1e, 0xcc, 0x08,
	0x87, 0xce, 0x74, 0xb1, 0xd0, 0x19, 0x50, 0xff,
	0xac, 0xef, 0x9f, 0x82, 0xda, 0x75, 0xda, 0x6d,
	0x89, 0xf3, 0x0b, 0xdc, 0x27, 0x98, 0x85, 0x01,
	0x68, 0xb7, 0xbd, 0x98, 0x83, 0xb1, 0xb0, 0x65,
	0x31, 0x71, 0x43, 0x05, 0xa7, 0x76, 0x63, 0xe4,
	0x7d, 0x61, 0x53, 0xc7, 0x3e, 0x3b, 0x82, 0x28,
	0x65, 0x07, 0xfe, 0x9e, 0xa3, 0x35, 0x2c, 0xdc,
	0x9e, 0x05, 0x7c, 0x9a, 0x69, 0xc6, 0x9f, 0xc2,
	0x3f, 0x94, 0x6b, 0xad, 0xa4, 0x2b, 0x5d, 0x48,
	0x9e, 0x2c, 0xad, 0xd2, 0x89, 0x49, 0xdc, 0xdb,
	0x55, 0x49, 0x56, 0xaf, 0xe9, 0x0e, 0x37, 0xe7,
	0x1f, 0x42, 0x6a, 0x7c, 0xac, 0xe8, 0x1b, 0xbb,
	0x21, 0x82, 0x14, 0x72, 0x17, 0x64, 0xf0, 0x3c,
	0x3d, 0xc1, 0x43, 0x27, 0x27, 0x9f, 0xe9, 0x21,
	0xf2, 0x2f, 0xf7, 0xfa, 0x3c, 0xed, 0xbf, 0xab,
	0xab, 0xb7, 0x3c, 0x6d, 0x1e, 0x85, 0x9f, 0x77,
	0x4f, 0x69, 0x09, 0x4e, 0xed, 0x13, 0x84, 0x40,
	0x1a, 0xc6, 0xa1, 0xd9, 0x68, 0xb6, 0x18, 0x32,
	0x79, 0x25, 0x9e, 0xa6, 0x41, 0x30, 0xd1, 0xc2,
	0x7a, 0x8f, 0x0d, 0x46, 0xee, 0xda, 0xb0, 0xbf,
	0x64, 0x42, 0x59, 0x7e, 0x22, 0x88, 0xd6, 0x52,
	0xec, 0xed, 0xc4, 0x13, 0xb1, 0x7f, 0x5c, 0x77,
	0x4c, 0xfd, 0x22, 0x90, 0xd3, 0xe3, 0xa9, 0xc1,
	0x0f, 0x25, 0xac, 0xd5, 0x04, 0x84, 0xe6, 0xa8,
	0xc7, 0xb4, 0x4f, 0xa2, 0x67, 0xae, 0xaa, 0x92,
	0xe9, 0x0a, 0xed, 0x45, 0x5b, 0xf0, 0x1b, 0x69,
	0xec, 0xaf, 0x7d, 0xf2, 0x71, 0x25, 0xbf, 0x92,
	0xd4, 0xd0, 0x5b, 0xde, 0x5a, 0x2d, 0x18, 0x8e
};
#endif

void load_dsa_key_blob(dsa_ctx_t* ctx){
	if(ctx->priv.wordv){
		free(ctx->priv.wordv);
	}
	ctx->priv.wordv = malloc(ALL_LEN_B);
	if(ctx->priv.wordv==NULL){
		cli_putstr_P(PSTR("\r\nERROR: OUT OF MEMORY!!!"));
		return;
	}
	memcpy_P(ctx->priv.wordv, dsa_key_blob, ALL_LEN_B);
	ctx->priv.length_W=PRIV_LEN_B;
	ctx->pub.wordv = ctx->priv.wordv+PRIV_LEN_B;
	ctx->pub.length_W = PUB_LEN_B;
	ctx->domain.p.wordv = ctx->priv.wordv+PRIV_LEN_B+PUB_LEN_B;
	ctx->domain.p.length_W = P_LEN_B;
	ctx->domain.q.wordv = ctx->priv.wordv+PRIV_LEN_B+PUB_LEN_B+P_LEN_B;
	ctx->domain.q.length_W = Q_LEN_B;
	ctx->domain.g.wordv = ctx->priv.wordv+PRIV_LEN_B+PUB_LEN_B+P_LEN_B+Q_LEN_B;
	ctx->domain.g.length_W = G_LEN_B;

	bigint_changeendianess(&(ctx->priv));
	bigint_changeendianess(&(ctx->pub));
	bigint_changeendianess(&(ctx->domain.p));
	bigint_changeendianess(&(ctx->domain.q));
	bigint_changeendianess(&(ctx->domain.g));

	bigint_adjust(&(ctx->priv));
	bigint_adjust(&(ctx->pub));
	bigint_adjust(&(ctx->domain.p));
	bigint_adjust(&(ctx->domain.q));
	bigint_adjust(&(ctx->domain.g));
}
