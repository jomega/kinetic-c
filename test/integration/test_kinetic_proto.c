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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "protobuf-c/protobuf-c.h"
#include "kinetic_types.h"
#include "kinetic_proto.h"
#include "unity.h"

void setUp(void)
{
}

void tearDown(void)
{
}

void test_KineticProto_should_pack_and_unpack_protocol_buffers(void)
{
    size_t expectedLen;
    KineticProto_Message msg;
    KineticProto_Command cmd;
    KineticProto_Command_Header header;
    uint8_t buffer[256];
    ProtobufCBufferSimple bs = PROTOBUF_C_BUFFER_SIMPLE_INIT(buffer);
    uint8_t* packedMessage;
    uint8_t* packedCommand;

    KineticProto_Message__init(&msg);
    KineticProto_command__init(&cmd);
    KineticProto_command_header__init(&header);

    cmd.header = &header;

    // msg.commandBytes = &cmd;

    expectedLen = KineticProto_command__get_packed_size(&cmd);
    packedCommand = malloc(KineticProto_command__get_packed_size(&cmd));
    TEST_ASSERT_NOT_NULL_MESSAGE(packedCommand,
                                 "Failed dynamically allocating command buffer");
    TEST_ASSERT_EQUAL_MESSAGE(expectedLen,
                              KineticProto_command__pack(&cmd, packedCommand),
                              "Packed size command invalid");
    TEST_ASSERT_EQUAL_MESSAGE(expectedLen,
                              KineticProto_command__get_packed_size(&cmd),
                              "Inspected packed command size invalid");
    TEST_ASSERT_EQUAL_MESSAGE(expectedLen,
                              KineticProto_command__pack_to_buffer(&cmd, &bs.base),
                              "Packed BufferSimple command size invalid");


    expectedLen = KineticProto_Message__get_packed_size(&msg);
    packedMessage = malloc(KineticProto_Message__get_packed_size(&msg));
    TEST_ASSERT_NOT_NULL_MESSAGE(packedMessage,
                                 "Failed dynamically allocating buffer");
    TEST_ASSERT_EQUAL_MESSAGE(expectedLen,
                              KineticProto_Message__pack(&msg, packedMessage),
                              "Packed size invalid");
    TEST_ASSERT_EQUAL_MESSAGE(expectedLen,
                              KineticProto_Message__get_packed_size(&msg),
                              "Inspected packed size invalid");
    TEST_ASSERT_EQUAL_MESSAGE(expectedLen,
                              KineticProto_Message__pack_to_buffer(&msg, &bs.base),
                              "Packed BufferSimple size invalid");

    // Validate the both packed buffers are equal
    // TEST_ASSERT_EQUAL_HEX8_ARRAY_MESSAGE(bs.data, packedMessage, expectedLen,
    //                                      "Packed proto buffers do not match");
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR(&bs);

    // Free dynamically allocated memory
    free(packedMessage);
    free(packedCommand);
}

void test_KinetiProto_double_packing_should_work(void)
{
    size_t expectedPackedLen, actualPackedLen;
    uint8_t packBuf[128];

    KineticProto_Message msg;
    KineticProto_Message__init(&msg);
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(expectedPackedLen == 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);

    msg.has_authType = true;
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(KineticProto_Message__get_packed_size(&msg) > 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);

    msg.authType = KINETIC_PROTO_MESSAGE_AUTH_TYPE_HMACAUTH;
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(KineticProto_Message__get_packed_size(&msg) > 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);

    KineticProto_Message_HMACauth hmacAuth;
    KineticProto_Message_hmacauth__init(&hmacAuth);
    msg.hmacAuth = &hmacAuth;
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(KineticProto_Message__get_packed_size(&msg) > 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);

    hmacAuth.has_identity = true;
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(KineticProto_Message__get_packed_size(&msg) > 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);

    hmacAuth.identity = 17;
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(KineticProto_Message__get_packed_size(&msg) > 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);

    uint8_t hmacData[] = {1,2,3,4,5};
    hmacAuth.hmac = (ProtobufCBinaryData) {.data = hmacData, .len = sizeof(hmacData)};
    hmacAuth.has_hmac = true;
    expectedPackedLen = KineticProto_Message__get_packed_size(&msg);
    TEST_ASSERT_TRUE(KineticProto_Message__get_packed_size(&msg) > 0);
    actualPackedLen = KineticProto_Message__pack(&msg, packBuf);
    TEST_ASSERT_EQUAL(expectedPackedLen, actualPackedLen);
}

#if 0
void test_KineticProto_should_pass_data_accurately_through_raw_buffers(void)
{
    uint8_t* packed;
    KineticProto* unpacked;
    KineticProto proto;
    KineticProto_Command cmd;
    KineticProto_Command_Header header;

    KineticProto__init(&proto);
    KineticProto_command__init(&cmd);
    proto.command = &cmd;
    KineticProto_command_header__init(&header);
    header.clusterVersion = 12345678;
    header.has_clusterVersion = true;
    header.identity = -12345678;
    header.has_identity = true;
    cmd.header = &header;

    // Pack the buffer
    packed = malloc(KineticProto_Message__get_packed_size(&proto));
    KineticProto__pack(&proto, packed);

    // Unpack and verify the raw buffer results
    unpacked = KineticProto__unpack(NULL,
                                    KineticProto_Message__get_packed_size(&proto), packed);
    TEST_ASSERT_NOT_NULL_MESSAGE(unpacked,
                                 "Unpack method returned NULL");
    TEST_ASSERT_TRUE_MESSAGE(unpacked->command->header->has_identity,
                             "Command header identity reported as unavailable");
    TEST_ASSERT_EQUAL_INT64_MESSAGE(-12345678ul,
                                    unpacked->command->header->identity,
                                    "Command header identity invalid");
    TEST_ASSERT_TRUE_MESSAGE(unpacked->command->header->has_clusterVersion,
                             "Command header cluster version reported as unavailable");
    TEST_ASSERT_EQUAL_INT64_MESSAGE(12345678ul,
                                    unpacked->command->header->clusterVersion,
                                    "Command header cluster version invalid");

    // Free dynamically allocated memory
    KineticProto__free_unpacked(unpacked, NULL);
    free(packed);
}

void test_KineticProto_should_pass_data_accurately_through_BufferSimple(void)
{
    KineticProto proto;
    KineticProto* unpacked;
    KineticProto_Command cmd;
    KineticProto_Command_Header header;
    uint8_t buffer[1024];
    ProtobufCBufferSimple bs = PROTOBUF_C_BUFFER_SIMPLE_INIT(buffer);

    KineticProto__init(&proto);
    KineticProto_command__init(&cmd);
    proto.command = &cmd;
    KineticProto_command_header__init(&header);
    header.clusterVersion = 12345678;
    header.has_clusterVersion = true;
    header.identity = -12345678;
    header.has_identity = true;
    cmd.header = &header;

    // Pack the buffer
    KineticProto__pack_to_buffer(&proto, &bs.base);

    // Unpack and verify the simple buffer results
    unpacked = KineticProto__unpack(NULL,
                                    KineticProto_Message__get_packed_size(&proto), bs.data);
    TEST_ASSERT_NOT_NULL_MESSAGE(unpacked, "Unpack method returned NULL");
    TEST_ASSERT_TRUE_MESSAGE(unpacked->command->header->has_identity,
                             "Command header identity reported as unavailable");
    TEST_ASSERT_EQUAL_INT64_MESSAGE(-12345678ul,
                                    unpacked->command->header->identity,
                                    "Command header identity invalid");
    TEST_ASSERT_TRUE_MESSAGE(unpacked->command->header->has_clusterVersion,
                             "Command header cluster version reported as unavailable");
    TEST_ASSERT_EQUAL_INT64_MESSAGE(12345678ul,
                                    unpacked->command->header->clusterVersion,
                                    "Command header cluster version invalid");

    // Free dynamically allocated memory
    KineticProto__free_unpacked(unpacked, NULL);
}
#endif