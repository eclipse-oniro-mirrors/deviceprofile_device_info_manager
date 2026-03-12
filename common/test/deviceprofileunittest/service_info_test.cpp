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

#include "message_parcel.h"
#include "service_info.h"

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

void ServiceInfoTest::SetUpTestCase() {}

void ServiceInfoTest::TearDownTestCase() {}

void ServiceInfoTest::SetUp() {}

void ServiceInfoTest::TearDown() {}

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
