/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <string>

#include "service_info.h"
#include "distributed_device_profile_constants.h"
#include "message_parcel.h"


using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
class ServiceInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ServiceInfoTest::SetUpTestCase()
{
}

void ServiceInfoTest::TearDownTestCase()
{
}

void ServiceInfoTest::SetUp()
{
}

void ServiceInfoTest::TearDown()
{
}

/**
 * @tc.name: GetUdid_001
 * @tc.desc: GetUdid with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUdid_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUdid_002
 * @tc.desc: GetUdid after SetUdid with valid string
 *           Step 1: Create ServiceInfo and set udid to "test_udid_123"
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value is "test_udid_123"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUdid_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testUdid = "test_udid_123";
    serviceInfo.SetUdid(testUdid);
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "test_udid_123");
}

/**
 * @tc.name: GetUdid_003
 * @tc.desc: GetUdid after SetUdid with empty string
 *           Step 1: Create ServiceInfo and set udid to empty string
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUdid_003, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testUdid = "";
    serviceInfo.SetUdid(testUdid);
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetUdid_004
 * @tc.desc: GetUdid after SetUdid multiple times
 *           Step 1: Create ServiceInfo and set udid multiple times
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value is the last set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUdid_004, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUdid("udid_001");
    serviceInfo.SetUdid("udid_002");
    serviceInfo.SetUdid("udid_final");
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "udid_final");
}

/**
 * @tc.name: GetUdid_005
 * @tc.desc: GetUdid after SetUdid with special characters
 *           Step 1: Create ServiceInfo and set udid with special characters
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value matches the set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUdid_005, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testUdid = "test-udid_123!@#$%";
    serviceInfo.SetUdid(testUdid);
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "test-udid_123!@#$%");
}

/**
 * @tc.name: SetUdid_001
 * @tc.desc: SetUdid with valid string and verify through GetUdid
 *           Step 1: Create ServiceInfo and set udid to "test_set_udid"
 *           Step 2: Call GetUdid to verify
 *           Step 3: Verify return value is "test_set_udid"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUdid_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testUdid = "test_set_udid";
    serviceInfo.SetUdid(testUdid);
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "test_set_udid");
}

/**
 * @tc.name: SetUdid_002
 * @tc.desc: SetUdid with empty string
 *           Step 1: Create ServiceInfo, set udid, then set to empty
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUdid_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUdid("initial_value");
    serviceInfo.SetUdid("");
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: SetUdid_003
 * @tc.desc: SetUdid with long string
 *           Step 1: Create ServiceInfo and set udid with long string
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value matches the set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUdid_003, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string longUdid(1000, 'a');
    serviceInfo.SetUdid(longUdid);
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, longUdid);
}

/**
 * @tc.name: SetUdid_004
 * @tc.desc: SetUdid multiple times with different values
 *           Step 1: Create ServiceInfo and set udid multiple times
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value is the last set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUdid_004, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUdid("first_udid");
    serviceInfo.SetUdid("second_udid");
    serviceInfo.SetUdid("third_udid");
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "third_udid");
}

/**
 * @tc.name: SetUdid_005
 * @tc.desc: SetUdid with whitespace string
 *           Step 1: Create ServiceInfo and set udid with whitespace
 *           Step 2: Call GetUdid
 *           Step 3: Verify return value matches the set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUdid_005, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testUdid = "   ";
    serviceInfo.SetUdid(testUdid);
    std::string result = serviceInfo.GetUdid();
    EXPECT_EQ(result, "   ");
}

/**
 * @tc.name: GetUserId_001
 * @tc.desc: GetUserId with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is DEFAULT_USER_ID
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUserId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, DEFAULT_USER_ID);
}

/**
 * @tc.name: GetUserId_002
 * @tc.desc: GetUserId after SetUserId with positive value
 *           Step 1: Create ServiceInfo and set userId to 100
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is 100
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUserId_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = 100;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, 100);
}

/**
 * @tc.name: GetUserId_003
 * @tc.desc: GetUserId after SetUserId with zero
 *           Step 1: Create ServiceInfo and set userId to 0
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is 0
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUserId_003, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = 0;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: GetUserId_004
 * @tc.desc: GetUserId after SetUserId with negative value
 *           Step 1: Create ServiceInfo and set userId to -1
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is -1
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUserId_004, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = -1;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: GetUserId_005
 * @tc.desc: GetUserId after SetUserId with maximum int32_t value
 *           Step 1: Create ServiceInfo and set userId to INT32_MAX
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is INT32_MAX
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUserId_005, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = INT32_MAX;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, INT32_MAX);
}

/**
 * @tc.name: GetUserId_006
 * @tc.desc: GetUserId after SetUserId multiple times
 *           Step 1: Create ServiceInfo and set userId multiple times
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is the last set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetUserId_006, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUserId(100);
    serviceInfo.SetUserId(200);
    serviceInfo.SetUserId(300);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, 300);
}

/**
 * @tc.name: SetUserId_001
 * @tc.desc: SetUserId with positive value and verify through GetUserId
 *           Step 1: Create ServiceInfo and set userId to 999
 *           Step 2: Call GetUserId to verify
 *           Step 3: Verify return value is 999
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUserId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = 999;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, 999);
}

/**
 * @tc.name: SetUserId_002
 * @tc.desc: SetUserId with negative value
 *           Step 1: Create ServiceInfo and set userId to -100
 *           Step 2: Call GetUserId to verify
 *           Step 3: Verify return value is -100
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUserId_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = -100;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, -100);
}

/**
 * @tc.name: SetUserId_003
 * @tc.desc: SetUserId multiple times with different values
 *           Step 1: Create ServiceInfo and set userId multiple times
 *           Step 2: Call GetUserId
 *           Step 3: Verify return value is the last set value
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUserId_003, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUserId(1);
    serviceInfo.SetUserId(100);
    serviceInfo.SetUserId(INT32_MAX);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, INT32_MAX);
}

/**
 * @tc.name: SetUserId_004
 * @tc.desc: SetUserId with zero value
 *           Step 1: Create ServiceInfo and set userId to 0
 *           Step 2: Call GetUserId to verify
 *           Step 3: Verify return value is 0
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetUserId_004, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testUserId = 0;
    serviceInfo.SetUserId(testUserId);
    int32_t result = serviceInfo.GetUserId();
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: GetDisplayId_001
 * @tc.desc: GetDisplayId with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetDisplayId
 *           Step 3: Verify return value is DEFAULT_DISPLAY_ID
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDisplayId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t result = serviceInfo.GetDisplayId();
    EXPECT_EQ(result, DEFAULT_DISPLAY_ID);
}

/**
 * @tc.name: GetDisplayId_002
 * @tc.desc: GetDisplayId after SetDisplayId with positive value
 *           Step 1: Create ServiceInfo and set displayId to 100
 *           Step 2: Call GetDisplayId
 *           Step 3: Verify return value is 100
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDisplayId_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testDisplayId = 100;
    serviceInfo.SetDisplayId(testDisplayId);
    int64_t result = serviceInfo.GetDisplayId();
    EXPECT_EQ(result, 100);
}

/**
 * @tc.name: GetDisplayId_003
 * @tc.desc: GetDisplayId after SetDisplayId with negative value
 *           Step 1: Create ServiceInfo and set displayId to -1
 *           Step 2: Call GetDisplayId
 *           Step 3: Verify return value is -1
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDisplayId_003, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testDisplayId = -1;
    serviceInfo.SetDisplayId(testDisplayId);
    int64_t result = serviceInfo.GetDisplayId();
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: SetDisplayId_001
 * @tc.desc: SetDisplayId with positive value and verify through GetDisplayId
 *           Step 1: Create ServiceInfo and set displayId to 999
 *           Step 2: Call GetDisplayId to verify
 *           Step 3: Verify return value is 999
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetDisplayId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testDisplayId = 999;
    serviceInfo.SetDisplayId(testDisplayId);
    int64_t result = serviceInfo.GetDisplayId();
    EXPECT_EQ(result, 999);
}

/**
 * @tc.name: GetServiceOwnerTokenId_001
 * @tc.desc: GetServiceOwnerTokenId with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceOwnerTokenId
 *           Step 3: Verify return value is DEFAULT_SERVICE_OWNER_TOKENID
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceOwnerTokenId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t result = serviceInfo.GetServiceOwnerTokenId();
    EXPECT_EQ(result, DEFAULT_SERVICE_OWNER_TOKENID);
}

/**
 * @tc.name: GetServiceOwnerTokenId_002
 * @tc.desc: GetServiceOwnerTokenId after SetServiceOwnerTokenId
 *           Step 1: Create ServiceInfo and set serviceOwnerTokenId to 100
 *           Step 2: Call GetServiceOwnerTokenId
 *           Step 3: Verify return value is 100
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceOwnerTokenId_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testTokenId = 100;
    serviceInfo.SetServiceOwnerTokenId(testTokenId);
    int32_t result = serviceInfo.GetServiceOwnerTokenId();
    EXPECT_EQ(result, 100);
}

/**
 * @tc.name: SetServiceOwnerTokenId_001
 * @tc.desc: SetServiceOwnerTokenId with positive value and verify
 *           Step 1: Create ServiceInfo and set serviceOwnerTokenId to 888
 *           Step 2: Call GetServiceOwnerTokenId to verify
 *           Step 3: Verify return value is 888
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceOwnerTokenId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testTokenId = 888;
    serviceInfo.SetServiceOwnerTokenId(testTokenId);
    int32_t result = serviceInfo.GetServiceOwnerTokenId();
    EXPECT_EQ(result, 888);
}

/**
 * @tc.name: GetServiceOwnerPkgName_001
 * @tc.desc: GetServiceOwnerPkgName with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceOwnerPkgName
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceOwnerPkgName_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetServiceOwnerPkgName();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetServiceOwnerPkgName_002
 * @tc.desc: GetServiceOwnerPkgName after SetServiceOwnerPkgName
 *           Step 1: Create ServiceInfo and set serviceOwnerPkgName to "test.pkg.name"
 *           Step 2: Call GetServiceOwnerPkgName
 *           Step 3: Verify return value is "test.pkg.name"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceOwnerPkgName_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testPkgName = "test.pkg.name";
    serviceInfo.SetServiceOwnerPkgName(testPkgName);
    std::string result = serviceInfo.GetServiceOwnerPkgName();
    EXPECT_EQ(result, "test.pkg.name");
}

/**
 * @tc.name: SetServiceOwnerPkgName_001
 * @tc.desc: SetServiceOwnerPkgName with valid string and verify
 *           Step 1: Create ServiceInfo and set serviceOwnerPkgName
 *           Step 2: Call GetServiceOwnerPkgName to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceOwnerPkgName_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testPkgName = "com.example.test";
    serviceInfo.SetServiceOwnerPkgName(testPkgName);
    std::string result = serviceInfo.GetServiceOwnerPkgName();
    EXPECT_EQ(result, "com.example.test");
}

/**
 * @tc.name: GetServiceRegisterTokenId_001
 * @tc.desc: GetServiceRegisterTokenId with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceRegisterTokenId
 *           Step 3: Verify return value is DEFAULT_SERVICE_REGISTER_TOKENID
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceRegisterTokenId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t result = serviceInfo.GetServiceRegisterTokenId();
    EXPECT_EQ(result, DEFAULT_SERVICE_REGISTER_TOKENID);
}

/**
 * @tc.name: GetServiceRegisterTokenId_002
 * @tc.desc: GetServiceRegisterTokenId after SetServiceRegisterTokenId
 *           Step 1: Create ServiceInfo and set serviceRegisterTokenId to 200
 *           Step 2: Call GetServiceRegisterTokenId
 *           Step 3: Verify return value is 200
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceRegisterTokenId_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testTokenId = 200;
    serviceInfo.SetServiceRegisterTokenId(testTokenId);
    int32_t result = serviceInfo.GetServiceRegisterTokenId();
    EXPECT_EQ(result, 200);
}

/**
 * @tc.name: SetServiceRegisterTokenId_001
 * @tc.desc: SetServiceRegisterTokenId with positive value and verify
 *           Step 1: Create ServiceInfo and set serviceRegisterTokenId to 777
 *           Step 2: Call GetServiceRegisterTokenId to verify
 *           Step 3: Verify return value is 777
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceRegisterTokenId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int32_t testTokenId = 777;
    serviceInfo.SetServiceRegisterTokenId(testTokenId);
    int32_t result = serviceInfo.GetServiceRegisterTokenId();
    EXPECT_EQ(result, 777);
}

/**
 * @tc.name: GetServiceId_001
 * @tc.desc: GetServiceId with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceId
 *           Step 3: Verify return value is DEFAULT_SERVICE_ID
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t result = serviceInfo.GetServiceId();
    EXPECT_EQ(result, DEFAULT_SERVICE_ID);
}

/**
 * @tc.name: GetServiceId_002
 * @tc.desc: GetServiceId after SetServiceId with positive value
 *           Step 1: Create ServiceInfo and set serviceId to 12345
 *           Step 2: Call GetServiceId
 *           Step 3: Verify return value is 12345
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceId_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testServiceId = 12345;
    serviceInfo.SetServiceId(testServiceId);
    int64_t result = serviceInfo.GetServiceId();
    EXPECT_EQ(result, 12345);
}

/**
 * @tc.name: SetServiceId_001
 * @tc.desc: SetServiceId with positive value and verify
 *           Step 1: Create ServiceInfo and set serviceId to 54321
 *           Step 2: Call GetServiceId to verify
 *           Step 3: Verify return value is 54321
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceId_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testServiceId = 54321;
    serviceInfo.SetServiceId(testServiceId);
    int64_t result = serviceInfo.GetServiceId();
    EXPECT_EQ(result, 54321);
}

/**
 * @tc.name: GetTimeStamp_001
 * @tc.desc: GetTimeStamp with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetTimeStamp
 *           Step 3: Verify return value is DEFAULT_TIMESTAMP
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetTimeStamp_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t result = serviceInfo.GetTimeStamp();
    EXPECT_EQ(result, DEFAULT_TIMESTAMP);
}

/**
 * @tc.name: GetTimeStamp_002
 * @tc.desc: GetTimeStamp after SetTimeStamp
 *           Step 1: Create ServiceInfo and set timeStamp to 99999
 *           Step 2: Call GetTimeStamp
 *           Step 3: Verify return value is 99999
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetTimeStamp_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testTimeStamp = 99999;
    serviceInfo.SetTimeStamp(testTimeStamp);
    int64_t result = serviceInfo.GetTimeStamp();
    EXPECT_EQ(result, 99999);
}

/**
 * @tc.name: SetTimeStamp_001
 * @tc.desc: SetTimeStamp with positive value and verify
 *           Step 1: Create ServiceInfo and set timeStamp to 88888
 *           Step 2: Call GetTimeStamp to verify
 *           Step 3: Verify return value is 88888
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetTimeStamp_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int64_t testTimeStamp = 88888;
    serviceInfo.SetTimeStamp(testTimeStamp);
    int64_t result = serviceInfo.GetTimeStamp();
    EXPECT_EQ(result, 88888);
}

/**
 * @tc.name: GetPublishState_001
 * @tc.desc: GetPublishState with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetPublishState
 *           Step 3: Verify return value is DEFAULT_PUBLISH_STATE
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetPublishState_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int8_t result = serviceInfo.GetPublishState();
    EXPECT_EQ(result, DEFAULT_PUBLISH_STATE);
}

/**
 * @tc.name: GetPublishState_002
 * @tc.desc: GetPublishState after SetPublishState
 *           Step 1: Create ServiceInfo and set publishState to 1
 *           Step 2: Call GetPublishState
 *           Step 3: Verify return value is 1
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetPublishState_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int8_t testPublishState = 1;
    serviceInfo.SetPublishState(testPublishState);
    int8_t result = serviceInfo.GetPublishState();
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: SetPublishState_001
 * @tc.desc: SetPublishState with value and verify
 *           Step 1: Create ServiceInfo and set publishState to 2
 *           Step 2: Call GetPublishState to verify
 *           Step 3: Verify return value is 2
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetPublishState_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    int8_t testPublishState = 2;
    serviceInfo.SetPublishState(testPublishState);
    int8_t result = serviceInfo.GetPublishState();
    EXPECT_EQ(result, 2);
}

/**
 * @tc.name: GetServiceType_001
 * @tc.desc: GetServiceType with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceType
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceType_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetServiceType();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetServiceType_002
 * @tc.desc: GetServiceType after SetServiceType
 *           Step 1: Create ServiceInfo and set serviceType to "test_type"
 *           Step 2: Call GetServiceType
 *           Step 3: Verify return value is "test_type"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceType_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testServiceType = "test_type";
    serviceInfo.SetServiceType(testServiceType);
    std::string result = serviceInfo.GetServiceType();
    EXPECT_EQ(result, "test_type");
}

/**
 * @tc.name: SetServiceType_001
 * @tc.desc: SetServiceType with valid string and verify
 *           Step 1: Create ServiceInfo and set serviceType
 *           Step 2: Call GetServiceType to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceType_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testServiceType = "service.test.type";
    serviceInfo.SetServiceType(testServiceType);
    std::string result = serviceInfo.GetServiceType();
    EXPECT_EQ(result, "service.test.type");
}

/**
 * @tc.name: GetServiceName_001
 * @tc.desc: GetServiceName with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceName
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceName_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetServiceName();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetServiceName_002
 * @tc.desc: GetServiceName after SetServiceName
 *           Step 1: Create ServiceInfo and set serviceName to "test_service_name"
 *           Step 2: Call GetServiceName
 *           Step 3: Verify return value is "test_service_name"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceName_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testServiceName = "test_service_name";
    serviceInfo.SetServiceName(testServiceName);
    std::string result = serviceInfo.GetServiceName();
    EXPECT_EQ(result, "test_service_name");
}

/**
 * @tc.name: SetServiceName_001
 * @tc.desc: SetServiceName with valid string and verify
 *           Step 1: Create ServiceInfo and set serviceName
 *           Step 2: Call GetServiceName to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceName_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testServiceName = "my.test.service";
    serviceInfo.SetServiceName(testServiceName);
    std::string result = serviceInfo.GetServiceName();
    EXPECT_EQ(result, "my.test.service");
}

/**
 * @tc.name: GetServiceDisplayName_001
 * @tc.desc: GetServiceDisplayName with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceDisplayName
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceDisplayName_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetServiceDisplayName();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetServiceDisplayName_002
 * @tc.desc: GetServiceDisplayName after SetServiceDisplayName
 *           Step 1: Create ServiceInfo and set serviceDisplayName to "Test Display Name"
 *           Step 2: Call GetServiceDisplayName
 *           Step 3: Verify return value is "Test Display Name"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceDisplayName_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testDisplayName = "Test Display Name";
    serviceInfo.SetServiceDisplayName(testDisplayName);
    std::string result = serviceInfo.GetServiceDisplayName();
    EXPECT_EQ(result, "Test Display Name");
}

/**
 * @tc.name: SetServiceDisplayName_001
 * @tc.desc: SetServiceDisplayName with valid string and verify
 *           Step 1: Create ServiceInfo and set serviceDisplayName
 *           Step 2: Call GetServiceDisplayName to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceDisplayName_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testDisplayName = "My Service Display";
    serviceInfo.SetServiceDisplayName(testDisplayName);
    std::string result = serviceInfo.GetServiceDisplayName();
    EXPECT_EQ(result, "My Service Display");
}

/**
 * @tc.name: GetCustomData_001
 * @tc.desc: GetCustomData with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetCustomData
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetCustomData_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetCustomData();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetCustomData_002
 * @tc.desc: GetCustomData after SetCustomData
 *           Step 1: Create ServiceInfo and set customData to "custom_data"
 *           Step 2: Call GetCustomData
 *           Step 3: Verify return value is "custom_data"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetCustomData_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testCustomData = "custom_data";
    serviceInfo.SetCustomData(testCustomData);
    std::string result = serviceInfo.GetCustomData();
    EXPECT_EQ(result, "custom_data");
}

/**
 * @tc.name: SetCustomData_001
 * @tc.desc: SetCustomData with valid string and verify
 *           Step 1: Create ServiceInfo and set customData
 *           Step 2: Call GetCustomData to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetCustomData_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testCustomData = "{\"key\":\"value\"}";
    serviceInfo.SetCustomData(testCustomData);
    std::string result = serviceInfo.GetCustomData();
    EXPECT_EQ(result, "{\"key\":\"value\"}");
}

/**
 * @tc.name: GetServiceCode_001
 * @tc.desc: GetServiceCode with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetServiceCode
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceCode_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetServiceCode();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetServiceCode_002
 * @tc.desc: GetServiceCode after SetServiceCode
 *           Step 1: Create ServiceInfo and set serviceCode to "code123"
 *           Step 2: Call GetServiceCode
 *           Step 3: Verify return value is "code123"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetServiceCode_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testServiceCode = "code123";
    serviceInfo.SetServiceCode(testServiceCode);
    std::string result = serviceInfo.GetServiceCode();
    EXPECT_EQ(result, "code123");
}

/**
 * @tc.name: SetServiceCode_001
 * @tc.desc: SetServiceCode with valid string and verify
 *           Step 1: Create ServiceInfo and set serviceCode
 *           Step 2: Call GetServiceCode to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetServiceCode_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testServiceCode = "service.code.456";
    serviceInfo.SetServiceCode(testServiceCode);
    std::string result = serviceInfo.GetServiceCode();
    EXPECT_EQ(result, "service.code.456");
}

/**
 * @tc.name: GetDataLen_001
 * @tc.desc: GetDataLen with default value
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetDataLen
 *           Step 3: Verify return value is 0
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDataLen_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    uint32_t result = serviceInfo.GetDataLen();
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: GetDataLen_002
 * @tc.desc: GetDataLen after SetDataLen
 *           Step 1: Create ServiceInfo and set dataLen to 1024
 *           Step 2: Call GetDataLen
 *           Step 3: Verify return value is 1024
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDataLen_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    uint32_t testDataLen = 1024;
    serviceInfo.SetDataLen(testDataLen);
    uint32_t result = serviceInfo.GetDataLen();
    EXPECT_EQ(result, 1024);
}

/**
 * @tc.name: SetDataLen_001
 * @tc.desc: SetDataLen with value and verify
 *           Step 1: Create ServiceInfo and set dataLen to 2048
 *           Step 2: Call GetDataLen to verify
 *           Step 3: Verify return value is 2048
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetDataLen_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    uint32_t testDataLen = 2048;
    serviceInfo.SetDataLen(testDataLen);
    uint32_t result = serviceInfo.GetDataLen();
    EXPECT_EQ(result, 2048);
}

/**
 * @tc.name: GetExtraData_001
 * @tc.desc: GetExtraData with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetExtraData
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetExtraData_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetExtraData();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetExtraData_002
 * @tc.desc: GetExtraData after SetExtraData
 *           Step 1: Create ServiceInfo and set extraData to "extra_data"
 *           Step 2: Call GetExtraData
 *           Step 3: Verify return value is "extra_data"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetExtraData_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testExtraData = "extra_data";
    serviceInfo.SetExtraData(testExtraData);
    std::string result = serviceInfo.GetExtraData();
    EXPECT_EQ(result, "extra_data");
}

/**
 * @tc.name: SetExtraData_001
 * @tc.desc: SetExtraData with valid string and verify
 *           Step 1: Create ServiceInfo and set extraData
 *           Step 2: Call GetExtraData to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetExtraData_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testExtraData = "test.extra.data";
    serviceInfo.SetExtraData(testExtraData);
    std::string result = serviceInfo.GetExtraData();
    EXPECT_EQ(result, "test.extra.data");
}

/**
 * @tc.name: GetVersion_001
 * @tc.desc: GetVersion with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetVersion
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetVersion_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetVersion();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetVersion_002
 * @tc.desc: GetVersion after SetVersion
 *           Step 1: Create ServiceInfo and set version to "1.0.0"
 *           Step 2: Call GetVersion
 *           Step 3: Verify return value is "1.0.0"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetVersion_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testVersion = "1.0.0";
    serviceInfo.SetVersion(testVersion);
    std::string result = serviceInfo.GetVersion();
    EXPECT_EQ(result, "1.0.0");
}

/**
 * @tc.name: SetVersion_001
 * @tc.desc: SetVersion with valid string and verify
 *           Step 1: Create ServiceInfo and set version
 *           Step 2: Call GetVersion to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetVersion_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testVersion = "2.5.1";
    serviceInfo.SetVersion(testVersion);
    std::string result = serviceInfo.GetVersion();
    EXPECT_EQ(result, "2.5.1");
}

/**
 * @tc.name: GetDescription_001
 * @tc.desc: GetDescription with default empty string
 *           Step 1: Create ServiceInfo with default constructor
 *           Step 2: Call GetDescription
 *           Step 3: Verify return value is empty string
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDescription_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string result = serviceInfo.GetDescription();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: GetDescription_002
 * @tc.desc: GetDescription after SetDescription
 *           Step 1: Create ServiceInfo and set description to "test description"
 *           Step 2: Call GetDescription
 *           Step 3: Verify return value is "test description"
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, GetDescription_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testDescription = "test description";
    serviceInfo.SetDescription(testDescription);
    std::string result = serviceInfo.GetDescription();
    EXPECT_EQ(result, "test description");
}

/**
 * @tc.name: SetDescription_001
 * @tc.desc: SetDescription with valid string and verify
 *           Step 1: Create ServiceInfo and set description
 *           Step 2: Call GetDescription to verify
 *           Step 3: Verify return value matches
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, SetDescription_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    std::string testDescription = "Service description for test";
    serviceInfo.SetDescription(testDescription);
    std::string result = serviceInfo.GetDescription();
    EXPECT_EQ(result, "Service description for test");
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Test dump method with default constructed ServiceInfo
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, Dump_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;

    std::string result = serviceInfo.dump();

    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Test dump method with ServiceInfo containing all fields set
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, Dump_002, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    serviceInfo.SetUdid("test-udid-12345");
    serviceInfo.SetUserId(100);
    serviceInfo.SetDisplayId(100001);
    serviceInfo.SetServiceOwnerTokenId(123456);
    serviceInfo.SetServiceOwnerPkgName("test.pkg.name");
    serviceInfo.SetServiceRegisterTokenId(654321);
    serviceInfo.SetServiceId(999999);
    serviceInfo.SetTimeStamp(1234567890);
    serviceInfo.SetPublishState(1);
    serviceInfo.SetServiceType("testType");
    serviceInfo.SetServiceName("testServiceName");
    serviceInfo.SetServiceDisplayName("Test Display Name");
    serviceInfo.SetCustomData("customDataValue");
    serviceInfo.SetServiceCode("serviceCode123");
    serviceInfo.SetDataLen(256);
    serviceInfo.SetExtraData("extraDataValue");
    serviceInfo.SetVersion("1.0.0");
    serviceInfo.SetDescription("Test Description");

    std::string result = serviceInfo.dump();

    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("\"userId\":100"), std::string::npos);
}

/**
 * @tc.name: OperatorLess_001
 * @tc.desc: Test operator< with different udid values
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorLess_001, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("aaa-udid");
    info2.SetUdid("bbb-udid");
    info1.SetUserId(100);
    info2.SetUserId(100);

    bool result = info1 < info2;

    EXPECT_TRUE(result);
}

/**
 * @tc.name: OperatorLess_002
 * @tc.desc: Test operator< with same udid but different userId values
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorLess_002, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("same-udid");
    info2.SetUdid("same-udid");
    info1.SetUserId(50);
    info2.SetUserId(100);

    bool result = info1 < info2;

    EXPECT_TRUE(result);
}

/**
 * @tc.name: OperatorLess_003
 * @tc.desc: Test operator< with same udid and userId but different serviceId values
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorLess_003, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("same-udid");
    info2.SetUdid("same-udid");
    info1.SetUserId(100);
    info2.SetUserId(100);
    info1.SetServiceId(1000);
    info2.SetServiceId(2000);

    bool result = info1 < info2;

    EXPECT_TRUE(result);
}

/**
 * @tc.name: OperatorLess_004
 * @tc.desc: Test operator< returns false when all fields are equal
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorLess_004, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("same-udid");
    info2.SetUdid("same-udid");
    info1.SetUserId(100);
    info2.SetUserId(100);
    info1.SetServiceId(1000);
    info2.SetServiceId(1000);

    bool result = info1 < info2;

    EXPECT_FALSE(result);
}

/**
 * @tc.name: OperatorLess_005
 * @tc.desc: Test operator< returns false when first object has greater udid
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorLess_005, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("zzz-udid");
    info2.SetUdid("aaa-udid");
    info1.SetUserId(100);
    info2.SetUserId(100);

    bool result = info1 < info2;

    EXPECT_FALSE(result);
}

/**
 * @tc.name: OperatorEqual_001
 * @tc.desc: Test operator== returns true when all key fields are equal
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorEqual_001, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("test-udid-123");
    info2.SetUdid("test-udid-123");
    info1.SetUserId(100);
    info2.SetUserId(100);
    info1.SetServiceId(5000);
    info2.SetServiceId(5000);

    bool result = info1 == info2;

    EXPECT_TRUE(result);
}

/**
 * @tc.name: OperatorEqual_002
 * @tc.desc: Test operator== returns false when udid is different
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorEqual_002, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("udid-111");
    info2.SetUdid("udid-222");
    info1.SetUserId(100);
    info2.SetUserId(100);
    info1.SetServiceId(5000);
    info2.SetServiceId(5000);

    bool result = info1 == info2;

    EXPECT_FALSE(result);
}

/**
 * @tc.name: OperatorEqual_003
 * @tc.desc: Test operator== returns false when userId is different
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorEqual_003, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("same-udid");
    info2.SetUdid("same-udid");
    info1.SetUserId(100);
    info2.SetUserId(200);
    info1.SetServiceId(5000);
    info2.SetServiceId(5000);

    bool result = info1 == info2;

    EXPECT_FALSE(result);
}

/**
 * @tc.name: OperatorEqual_004
 * @tc.desc: Test operator== returns false when serviceId is different
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorEqual_004, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("same-udid");
    info2.SetUdid("same-udid");
    info1.SetUserId(100);
    info2.SetUserId(100);
    info1.SetServiceId(3000);
    info2.SetServiceId(7000);

    bool result = info1 == info2;

    EXPECT_FALSE(result);
}

/**
 * @tc.name: OperatorEqual_005
 * @tc.desc: Test operator== with default constructed ServiceInfo objects
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorEqual_005, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;

    bool result = info1 == info2;

    EXPECT_TRUE(result);
}

/**
 * @tc.name: OperatorEqual_006
 * @tc.desc: Test operator== ignores non-key fields like serviceName
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, OperatorEqual_006, TestSize.Level1)
{
    ServiceInfo info1;
    ServiceInfo info2;
    info1.SetUdid("same-udid");
    info2.SetUdid("same-udid");
    info1.SetUserId(100);
    info2.SetUserId(100);
    info1.SetServiceId(5000);
    info2.SetServiceId(5000);
    info1.SetServiceName("service1");
    info2.SetServiceName("service2");

    bool result = info1 == info2;

    EXPECT_TRUE(result);
}

/**
 * @tc.name: UnMarshalling_001
 * @tc.desc: Test UnMarshalling with empty parcel returns false
 * @tc.type: FUNC
 */
HWTEST_F(ServiceInfoTest, UnMarshalling_001, TestSize.Level1)
{
    ServiceInfo serviceInfo;
    MessageParcel parcel;

    bool result = serviceInfo.UnMarshalling(parcel);

    EXPECT_FALSE(result);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
