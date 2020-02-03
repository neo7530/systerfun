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
#ifndef _SYSTER_DES_H
#define _SYSTER_DES_H

extern uint16_t _get_syster_cw(uint8_t ecm[16], uint8_t k64[8],uint8_t *out);

#endif
