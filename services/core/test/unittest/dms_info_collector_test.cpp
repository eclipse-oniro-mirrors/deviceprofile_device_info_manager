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

#include "dms_info_collector.h"

#include <memory>
#include <string>
#include <vector>

#include "cJSON.h"
#include "content_sensor_manager_utils.h"
#include "dms_constant.h"
#include "gtest/gtest.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
namespace {
constexpr size_t ONE_PROFILE = 1;
constexpr size_t TWO_PROFILES = 2;
const std::string SYNTHETIC_UDID = "synthetic-dms-collector-device";
}  // namespace
class DmsInfoCollectorFileTest : public testing::Test {
public:
    void SetUp() override
    {
        auto &utils = ContentSensorManagerUtils::GetInstance();
        savedUdid_ = utils.localUdid_;
        utils.localUdid_ = SYNTHETIC_UDID;
    }
    void TearDown() override
    {
        ContentSensorManagerUtils::GetInstance().localUdid_ = savedUdid_;
    }

private:
    std::string savedUdid_;
};

/**
 * @tc.name: ServiceUsesDmsIdentityAndCachedDevice_001
 * @tc.desc: Verify that service uses dms identity and cached device.
 * @tc.type: FUNC
 */
HWTEST_F(DmsInfoCollectorFileTest, ServiceUsesDmsIdentityAndCachedDevice_001, TestSize.Level1)
{
    DmsInfoCollector collector;
    std::vector<ServiceProfile> profiles;
    ASSERT_TRUE(collector.ConvertToProfile(profiles));
    ASSERT_EQ(profiles.size(), ONE_PROFILE);
    EXPECT_EQ(profiles.front().GetDeviceId(), SYNTHETIC_UDID);
    EXPECT_EQ(profiles.front().GetServiceName(), DistributedSchedule::Constants::DMS_SERVICE_ID);
    EXPECT_EQ(profiles.front().GetServiceType(), DistributedSchedule::Constants::DMS_SERVICE_ID);
}

/**
 * @tc.name: ExistingServiceProfilesAreNotOverwritten_001
 * @tc.desc: Verify that existing service profiles are not overwritten.
 * @tc.type: FUNC
 */
HWTEST_F(DmsInfoCollectorFileTest, ExistingServiceProfilesAreNotOverwritten_001, TestSize.Level1)
{
    DmsInfoCollector collector;
    ServiceProfile previous;
    previous.SetServiceName("existing-service");
    std::vector<ServiceProfile> profiles{previous};
    ASSERT_TRUE(collector.ConvertToProfile(profiles));
    ASSERT_EQ(profiles.size(), TWO_PROFILES);
    EXPECT_EQ(profiles.front().GetServiceName(), "existing-service");
    EXPECT_EQ(profiles.back().GetServiceName(), DistributedSchedule::Constants::DMS_SERVICE_ID);
}

/**
 * @tc.name: CharacteristicContainsPackageAndVersionJson_001
 * @tc.desc: Verify that characteristic contains package and version json.
 * @tc.type: FUNC
 */
HWTEST_F(DmsInfoCollectorFileTest, CharacteristicContainsPackageAndVersionJson_001, TestSize.Level1)
{
    DmsInfoCollector collector;
    std::vector<CharacteristicProfile> profiles;
    ASSERT_TRUE(collector.ConvertToProfile(profiles));
    ASSERT_EQ(profiles.size(), ONE_PROFILE);
    const auto &profile = profiles.front();
    EXPECT_EQ(profile.GetDeviceId(), SYNTHETIC_UDID);
    EXPECT_EQ(profile.GetServiceName(), DistributedSchedule::Constants::DMS_SERVICE_ID);
    EXPECT_EQ(profile.GetCharacteristicKey(), DistributedSchedule::Constants::DMS_CHAR_ID);
    std::unique_ptr<cJSON, decltype(&cJSON_Delete)> json(cJSON_Parse(profile.GetCharacteristicValue().c_str()),
                                                         cJSON_Delete);
    ASSERT_NE(json, nullptr);
    const auto *package = cJSON_GetObjectItemCaseSensitive(json.get(), DistributedSchedule::Constants::PACKAGE_NAMES);
    const auto *version = cJSON_GetObjectItemCaseSensitive(json.get(), DistributedSchedule::Constants::VERSIONS);
    ASSERT_NE(package, nullptr);
    ASSERT_TRUE(cJSON_IsString(package));
    ASSERT_NE(version, nullptr);
    ASSERT_TRUE(cJSON_IsString(version));
    EXPECT_STREQ(package->valuestring, DistributedSchedule::Constants::DMS_NAME);
    EXPECT_STREQ(version->valuestring, DistributedSchedule::Constants::DMS_VERSION);
}
}  // namespace DistributedDeviceProfile
}  // namespace OHOS
