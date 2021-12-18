/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "utils.h"

#define private public
#define protected public
#include "device_profile_errors.h"
#include "distributed_device_profile_client.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileCrudTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileCrudTest::SetUpTestCase()
{
}

void ProfileCrudTest::TearDownTestCase()
{
}

void ProfileCrudTest::SetUp()
{
}

void ProfileCrudTest::TearDown()
{
}

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_001, TestSize.Level1)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_TRUE(result == ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile_002
 * @tc.desc: put device profile with empty service type
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_002, TestSize.Level1)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_TRUE(result == ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile_003
 * @tc.desc: put device profile with empty characteristics
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_003, TestSize.Level1)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    // the result string is "null"
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_TRUE(result == ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile_004
 * @tc.desc: put device profile without set characteristics
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_004, TestSize.Level1)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_TRUE(result == ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile_005
 * @tc.desc: put device profile with normal value
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, PutDeviceProfile_005, TestSize.Level1)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 7;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profile);
    EXPECT_TRUE(result == ERR_OK);
}

/**
 * @tc.name: GetDeviceProfile_001
 * @tc.desc: get device profile with normal deviceid
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, GetDeviceProfile_001, TestSize.Level1)
{
    ServiceCharacteristicProfile profile;
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", "test", profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    auto json = nlohmann::json::parse(jsonData);
    EXPECT_EQ(json["testApiLevel"], 7);
}

/**
 * @tc.name: GetDeviceProfile_002
 * @tc.desc: get device profile with unnormal deviceid
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, GetDeviceProfile_002, TestSize.Level1)
{
    ServiceCharacteristicProfile profile;
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("123456789", "test", profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    EXPECT_TRUE(jsonData.empty());
}

/**
 * @tc.name: CollectDeviceProfile_001
 * @tc.desc: collect system profile infomation
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, CollectDeviceProfile_001, TestSize.Level1)
{
    ServiceCharacteristicProfile profile;
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", "system", profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    auto json = nlohmann::json::parse(jsonData);
    EXPECT_EQ(json["type"], 11);
}

/**
 * @tc.name: CollectDeviceProfile_002
 * @tc.desc: collect device profile infomation
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, CollectDeviceProfile_002, TestSize.Level1)
{
    ServiceCharacteristicProfile profile;
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", "device", profile);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    auto json = nlohmann::json::parse(jsonData);
    EXPECT_TRUE(!jsonData.empty());
}

/**
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: delete device profile
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, DeleteDeviceProfile_001, TestSize.Level1)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profilePut;
    profilePut.SetServiceId("fakeSystem");
    profilePut.SetServiceType("fakeSystem");
    nlohmann::json j;
    j["harmonyVersion"] = "2.2.0";
    profilePut.SetCharacteristicProfileJson(j.dump());
    int32_t result = DistributedDeviceProfileClient::GetInstance().PutDeviceProfile(profilePut);
    EXPECT_TRUE(result == ERR_OK);
    result = DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile("fakeSystem");
    EXPECT_TRUE(result == ERR_OK);

    ServiceCharacteristicProfile profileGet;
    DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", "fakeSystem", profileGet);
    auto profileStr = profileGet.GetCharacteristicProfileJson();
    auto profileJson = nlohmann::json::parse(profileStr, nullptr, false);
    if (!profileJson.is_discarded()) {
        EXPECT_TRUE(!profileJson.empty());
    }
}
}
}