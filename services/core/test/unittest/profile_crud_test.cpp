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
#include "device_profile_log.h"
#include "distributed_device_profile_client.h"
#include "hisysevent.h"
#include "nlohmann/json.hpp"
#include "syscap_info_collector.h"
#include "syscap_interface.h"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::HiviewDFX;
namespace {
    const std::string TAG = "SyscapInfoCollector";
    const std::string SERVICE_ID = "syscap";
    const std::string SERVICE_TYPE = "syscap";
    const std::string CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
    const std::string CHARACTER_OS_SYSCAP = "ossyscap";
    const std::string DEVICE_PROFILE_SYNC_FAILED = "DEVICE_PROFILE_SYNC_FAILED";
    const std::string FAULT_CODE_KEY = "FAULT_CODE";
    const std::string DOMAIN_NAME = std::string(HiSysEvent::Domain::DEVICE_PROFILE);
}
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
HWTEST_F(ProfileCrudTest, PutDeviceProfile_001, TestSize.Level0)
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
HWTEST_F(ProfileCrudTest, PutDeviceProfile_002, TestSize.Level0)
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
HWTEST_F(ProfileCrudTest, PutDeviceProfile_003, TestSize.Level0)
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
HWTEST_F(ProfileCrudTest, PutDeviceProfile_004, TestSize.Level0)
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
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, DeleteDeviceProfile_001, TestSize.Level0)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    int32_t result = DistributedDeviceProfileClient::GetInstance().DeleteDeviceProfile("");
    EXPECT_TRUE(result == ERR_DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetDeviceProfile_001
 * @tc.desc: get device profile with syscap
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, GetDeviceProfile_001, TestSize.Level2)
{
    auto dps = DistributedDeviceProfileClient::GetInstance().GetDeviceProfileService();
    if (dps == nullptr) {
        DTEST_LOG << "device profile service is nullptr" << std::endl;
        return;
    }

    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    int32_t result = DistributedDeviceProfileClient::GetInstance().GetDeviceProfile("", SERVICE_ID, profile);
    EXPECT_TRUE(result == ERR_DP_PERMISSION_DENIED);

    std::string jsonData = profile.GetCharacteristicProfileJson();
    DTEST_LOG << "jsonData:" << jsonData << std::endl;
    nlohmann::json jsonObject = nlohmann::json::parse(jsonData, nullptr, false);
    if (jsonObject.is_discarded()) {
        DTEST_LOG << "json parse faild" << std::endl;
        return;
    }

    std::vector<int> values = jsonObject[CHARACTER_OS_SYSCAP].get<std::vector<int>>();
    int intValues[PCID_MAIN_INTS];
    int i = 0;
    for (int value : values) {
        intValues[i++] = value;
    }

    char (*osOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    int32_t length;
    if (!DecodeOsSyscap((char *)intValues, &osOutput, &length)) {
        DTEST_LOG << "DecodeOsSyscap failed" << std::endl;
        return;
    }
    for (int i = 0; i < length; i++) {
        DTEST_LOG << "OsSyscap: " << *(osOutput + i) << std::endl;
    }

    std::string capabilities = jsonObject[CHARACTER_PRIVATE_SYSCAP];
    char (*priOutput)[SINGLE_SYSCAP_LEN] = nullptr;
    if (!DecodePrivateSyscap((char *)capabilities.c_str(), &priOutput, &length)) {
        DTEST_LOG << "DecodePrivateSyscap failed" << std::endl;
        return;
    }
    for (int i = 0; i < length; i++) {
        DTEST_LOG << "PrivateSyscap: " << *(priOutput + i) << std::endl;
    }
}

/**
 * @tc.name: DfxErrorPrint_001
 * @tc.desc: print hisysevent error event
 * @tc.type: FUNC
 */
HWTEST_F(ProfileCrudTest, DfxErrorPrint_001, TestSize.Level2)
{
    int ret = HiSysEvent::Write(DOMAIN_NAME, DEVICE_PROFILE_SYNC_FAILED,
        HiSysEvent::EventType::FAULT, FAULT_CODE_KEY, -1);
    EXPECT_TRUE(ret == 0);
}
}
}