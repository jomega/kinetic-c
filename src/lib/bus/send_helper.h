/*
* kinetic-c
* Copyright (C) 2015 Seagate Technology.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*/
#ifndef SEND_HELPER_H
#define SEND_HELPER_H

#include "bus_types.h"
#include "bus_internal_types.h"

typedef enum {
    SHHW_OK,
    SHHW_DONE,
    SHHW_ERROR = -1,
} SendHelper_HandleWrite_res;

SendHelper_HandleWrite_res SendHelper_HandleWrite(bus *b, boxed_msg *box);

#endif
