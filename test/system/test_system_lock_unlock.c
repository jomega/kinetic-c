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
#include "system_test_fixture.h"
#include "kinetic_admin_client.h"

static char OldPinData[8];
static char NewPinData[8];
static ByteArray OldPin, NewPin;
static bool NewPinSet;
static bool Locked;

static uint8_t KeyData[1024];
static ByteBuffer KeyBuffer;
static uint8_t ExpectedKeyData[1024];
static ByteBuffer ExpectedKeyBuffer;
static uint8_t TagData[1024];
static ByteBuffer TagBuffer;
static uint8_t ExpectedTagData[1024];
static ByteBuffer ExpectedTagBuffer;
static ByteArray TestValue;
static uint8_t ValueData[KINETIC_OBJ_SIZE];
static ByteBuffer ValueBuffer;
static const char strKey[] = "GET system test blob";

void setUp(void)
{
    NewPinSet = false;
    Locked = false;

    SystemTestSetup(1);

    KeyBuffer = ByteBuffer_CreateAndAppendCString(KeyData, sizeof(KeyData), strKey);
    ExpectedKeyBuffer = ByteBuffer_CreateAndAppendCString(ExpectedKeyData, sizeof(ExpectedKeyData), strKey);
    TagBuffer = ByteBuffer_CreateAndAppendCString(TagData, sizeof(TagData), "SomeTagValue");
    ExpectedTagBuffer = ByteBuffer_CreateAndAppendCString(ExpectedTagData, sizeof(ExpectedTagData), "SomeTagValue");
    TestValue = ByteArray_CreateWithCString("lorem ipsum... blah blah blah... etc.");
    ValueBuffer = ByteBuffer_CreateAndAppendArray(ValueData, sizeof(ValueData), TestValue);

    // Setup to write some test data
    KineticEntry putEntry = {
        .key = KeyBuffer,
        .tag = TagBuffer,
        .algorithm = KINETIC_ALGORITHM_SHA1,
        .value = ValueBuffer,
        .force = true,
        .synchronization = KINETIC_SYNCHRONIZATION_FLUSH,
    };

    KineticStatus status = KineticClient_Put(Fixture.session, &putEntry, NULL);

    // Validate the object exists initially
    KineticEntry getEntry = {
        .key = KeyBuffer,
        .tag = TagBuffer,
        .algorithm = KINETIC_ALGORITHM_SHA1,
        .value = ValueBuffer,
        .force = true,
        .synchronization = KINETIC_SYNCHRONIZATION_WRITETHROUGH,
    };
    status = KineticClient_Get(Fixture.session, &getEntry, NULL);
    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
    TEST_ASSERT_EQUAL_ByteArray(putEntry.key.array, getEntry.key.array);
    TEST_ASSERT_EQUAL_ByteArray(putEntry.tag.array, getEntry.tag.array);
    TEST_ASSERT_EQUAL(putEntry.algorithm, getEntry.algorithm);
    TEST_ASSERT_EQUAL_ByteBuffer(putEntry.value, getEntry.value);

    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);

    // Set the erase PIN to something non-empty
    strcpy(NewPinData, SESSION_PIN);
    OldPin = ByteArray_Create(OldPinData, 0);
    NewPin = ByteArray_Create(NewPinData, strlen(NewPinData));
    status = KineticAdminClient_SetLockPin(Fixture.adminSession,
        OldPin, NewPin);
    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
    NewPinSet = true;
}

void tearDown(void)
{
    KineticStatus status;

    // Unlock if for some reason we are still locked in order to
    // prevent the device from staying in a locked/unusable state
    if (Locked) {
        status = KineticAdminClient_UnlockDevice(Fixture.adminSession, NewPin);
        TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
        Locked = false;
    }

    // Set the lock PIN back to empty
    if (NewPinSet) {
        status = KineticAdminClient_SetLockPin(Fixture.adminSession, NewPin, OldPin);
        TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
        NewPinSet = false;
    }

    SystemTestShutDown();
}

void test_KineticAdmin_should_lock_and_unlock_a_device(void)
{
    KineticStatus status;

    status = KineticAdminClient_LockDevice(Fixture.adminSession, NewPin);
    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
    Locked = true;

    /* Currently, the device appears to just hang up on us rather than
     * returning DEVICE_LOCKED (unlike the simulator). Some sort of
     * command here to confirm that the device lock succeeded would
     * be a better test. We need to check if the drive has another
     * interface that exposes this. */
    if (SystemTestIsUnderSimulator()) {
        // Validate the object cannot being accessed while locked
        KineticEntry getEntry = {
            .key = KeyBuffer,
            .tag = TagBuffer,
            .value = ValueBuffer,
            .force = true,
        };
        status = KineticClient_Get(Fixture.session, &getEntry, NULL);
        TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_DEVICE_LOCKED, status);
    }
    
    status = KineticAdminClient_UnlockDevice(Fixture.adminSession, NewPin);
    TEST_ASSERT_EQUAL_KineticStatus(KINETIC_STATUS_SUCCESS, status);
    Locked = false;
}
