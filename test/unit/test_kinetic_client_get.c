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

#include "kinetic_client.h"
#include "kinetic_types.h"
#include "kinetic_types_internal.h"
#include "kinetic_device_info.h"
#include "mock_kinetic_builder.h"
#include "mock_kinetic_operation.h"
#include "mock_kinetic_session.h"
#include "mock_kinetic_controller.h"
#include "mock_kinetic_bus.h"
#include "mock_kinetic_memory.h"
#include "mock_kinetic_allocator.h"
#include "mock_kinetic_resourcewaiter.h"

#include "kinetic_logger.h"
#include "kinetic.pb-c.h"
#include "protobuf-c/protobuf-c.h"
#include "byte_array.h"
#include "unity.h"
#include "unity_helper.h"

static KineticSession Session;

void setUp(void)
{
    KineticLogger_Init("stdout", 3);
}

void tearDown(void)
{
    KineticLogger_Close();
}

void test_KineticClient_Get_should_get_error_MISSING_KEY_if_called_without_key(void)
{
    uint8_t ValueData[64];
    ByteArray Value = ByteArray_Create(ValueData, sizeof(ValueData));
    ByteBuffer ValueBuffer = ByteBuffer_CreateWithArray(Value);

    KineticEntry entry = {.value = ValueBuffer};
    memset(&entry, 0, sizeof(entry));

    KineticStatus status = KineticClient_Get(&Session, &entry, NULL);

    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_MISSING_KEY, status);
}

void test_KineticClient_Get_should_get_error_MISSING_VALUE_BUFFER_if_called_without_value_buffer(void)
{
    uint8_t KeyData[64];
    ByteArray Key = ByteArray_Create(KeyData, sizeof(KeyData));
    ByteBuffer KeyBuffer = ByteBuffer_CreateWithArray(Key);

    KineticEntry entry = { .key = KeyBuffer };
    memset(&entry, 0, sizeof(entry));

    KineticStatus status = KineticClient_Get(&Session, &entry, NULL);

    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_MISSING_KEY, status);
}

void test_KineticClient_Get_should_execute_GET_operation(void)
{
    uint8_t KeyData[64];
    ByteArray Key = ByteArray_Create(KeyData, sizeof(KeyData));
    ByteBuffer KeyBuffer = ByteBuffer_CreateWithArray(Key);

    uint8_t ValueData[64];
    ByteArray Value = ByteArray_Create(ValueData, sizeof(ValueData));
    ByteBuffer ValueBuffer = ByteBuffer_CreateWithArray(Value);

    ByteBuffer_AppendDummyData(&KeyBuffer, Key.len);
    KineticEntry entry = {
        .key = KeyBuffer,
        .value = ValueBuffer,
    };
    KineticOperation operation;

    KineticAllocator_NewOperation_ExpectAndReturn(&Session, &operation);
    KineticBuilder_BuildGet_ExpectAndReturn(&operation, &entry, KINETIC_STATUS_SUCCESS);
    KineticController_ExecuteOperation_ExpectAndReturn(&operation, NULL, KINETIC_STATUS_CLUSTER_MISMATCH);

    KineticStatus status = KineticClient_Get(&Session, &entry, NULL);

    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_CLUSTER_MISMATCH, status);
}

void test_KineticClient_Get_should_execute_GET_operation_and_retrieve_only_metadata(void)
{
    uint8_t KeyData[64];
    ByteArray Key = ByteArray_Create(KeyData, sizeof(KeyData));

    ByteBuffer KeyBuffer = ByteBuffer_CreateWithArray(Key);
    ByteBuffer_AppendDummyData(&KeyBuffer, Key.len);
    KineticEntry entry = {
        .key = KeyBuffer,
        .metadataOnly = true,
    };

    KineticOperation operation;

    KineticAllocator_NewOperation_ExpectAndReturn(&Session, &operation);
    KineticBuilder_BuildGet_ExpectAndReturn(&operation, &entry, KINETIC_STATUS_SUCCESS);
    KineticController_ExecuteOperation_ExpectAndReturn(&operation, NULL, KINETIC_STATUS_SUCCESS);

    KineticStatus status = KineticClient_Get(&Session, &entry, NULL);

    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
}
