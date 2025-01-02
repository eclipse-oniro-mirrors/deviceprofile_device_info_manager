/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <dlfcn.h>
#include <fstream>

#include "static_capability_loader.h"
#include "config_policy_utils.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_errors.h"
#include "i_static_capability_collector.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;
namespace {
    const std::string TAG = "StaticCapabilityLoaderTest";
}

class StaticCapabilityLoaderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void StaticCapabilityLoaderTest::SetUpTestCase()
{
}

void StaticCapabilityLoaderTest::TearDownTestCase()
{
}

void StaticCapabilityLoaderTest::SetUp()
{
}

void StaticCapabilityLoaderTest::TearDown()
{
}

/*
 * @tc.name: Init_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, Init_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

#ifdef DEVICE_PROFILE_SWITCH_STATIC_ENABLE
/*
 * @tc.name: LoadStaticCapability_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticCapability_001, TestSize.Level1)
{
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadStaticCapability(staticCapability);
    EXPECT_EQ(ret, DP_SUCCESS);
}
#endif // DEVICE_PROFILE_SWITCH_STATIC_ENABLE

/*
 * @tc.name: LoadJsonFile_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadJsonFile_001, TestSize.Level1)
{
    std::string filePath = "";
    std::string fileContent;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadJsonFile(filePath, fileContent);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadJsonFile_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadJsonFile_002, TestSize.Level1)
{
    std::string filePath(MAX_STRING_LEN + 1, 'a');
    std::string fileContent;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadJsonFile(filePath, fileContent);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadJsonFile_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadJsonFile_003, TestSize.Level1)
{
    std::string filePath = "/invalid/path";
    std::string fileContent;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadJsonFile(filePath, fileContent);
    EXPECT_EQ(ret, DP_LOAD_JSON_FILE_FAIL);
}

/*
 * @tc.name: LoadJsonFile_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadJsonFile_004, TestSize.Level1)
{
    std::string filePath(PATH_MAX + 1, 'a');
    std::string fileContent;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadJsonFile(filePath, fileContent);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadJsonFile_005
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadJsonFile_005, TestSize.Level1)
{
    std::string filePath(PATH_MAX + 1, 'a');
    std::string fileContent;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadJsonFile(filePath, fileContent);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadJsonFile_006
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadJsonFile_006, TestSize.Level1)
{
    std::string filePath = "/system/lib64/libpasteboard_framework.z.so";
    std::string fileContent;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadJsonFile(filePath, fileContent);
    EXPECT_EQ(ret, DP_LOAD_JSON_FILE_FAIL);
}

/*
 * @tc.name: GetStaticCapability_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticCapability_001, TestSize.Level1)
{
    cJSON *staticCapabilityJson = cJSON_CreateObject();
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticCapability(staticCapabilityJson, staticCapability);
    EXPECT_EQ(ret, DP_PARSE_STATIC_CAP_FAIL);
    cJSON_Delete(staticCapabilityJson);
}

/*
 * @tc.name: GetStaticCapability_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticCapability_002, TestSize.Level1)
{
    cJSON *staticCapabilityJson = cJSON_CreateObject();
    cJSON_AddItemToObject(staticCapabilityJson, STATIC_CAPABILITY_ATTRIBUTE.c_str(), cJSON_CreateArray());
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticCapability(staticCapabilityJson, staticCapability);
    EXPECT_EQ(ret, DP_PARSE_STATIC_CAP_FAIL);
    cJSON_Delete(staticCapabilityJson);
}

/*
 * @tc.name: GetStaticCapability_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticCapability_003, TestSize.Level1)
{
    cJSON *staticCapabilityJson = cJSON_CreateObject();
    cJSON *staticCapabilities = cJSON_CreateArray();
    cJSON_AddItemToObject(staticCapabilityJson, STATIC_CAPABILITY_ATTRIBUTE.c_str(), staticCapabilities);
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticCapability(staticCapabilityJson, staticCapability);
    EXPECT_EQ(ret, DP_PARSE_STATIC_CAP_FAIL);
    cJSON_Delete(staticCapabilityJson);
}

/*
 * @tc.name: GetStaticInfo_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfo_001, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = EMPTY_STRING;
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfo(staticInfoJson, staticCapability,
            staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfo_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfo_002, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    cJSON_AddItemToObject(staticInfoJson, "test", cJSON_CreateString("test"));
    std::string staticVersion = EMPTY_STRING;
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfo(staticInfoJson, staticCapability,
            staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfo_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfo_003, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    cJSON_AddItemToObject(staticInfoJson, "test", cJSON_CreateString("test"));
    cJSON_AddItemToObject(staticInfoJson, "test2", cJSON_CreateString("test2"));
    std::string staticVersion = EMPTY_STRING;
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfo(staticInfoJson, staticCapability,
            staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoByVersion_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoByVersion_001, TestSize.Level1)
{
    std::string deviceId = "";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "1.0";
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().GetStaticInfoByVersion(deviceId, staticCapability,
        staticInfoJson, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoByVersion_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoByVersion_002, TestSize.Level1)
{
    std::string deviceId = "123456";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = nullptr;
    std::string staticVersion = "1.0";
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().GetStaticInfoByVersion(deviceId, staticCapability,
        staticInfoJson, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: GetStaticInfoByVersion_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoByVersion_003, TestSize.Level1)
{
    std::string deviceId = "123456";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "";
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().GetStaticInfoByVersion(deviceId, staticCapability,
        staticInfoJson, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoByVersion_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoByVersion_004, TestSize.Level1)
{
    std::string deviceId = "123456";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "1.0";
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().GetStaticInfoByVersion(deviceId, staticCapability,
        staticInfoJson, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
    cJSON_free(staticInfoJson);
}

/*
 * @tc.name: GetLatestStaticInfoJson_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetLatestStaticInfoJson_001, TestSize.Level1)
{
    const cJSON *staticInfoJson = nullptr;
    cJSON *ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetLatestStaticInfoJson(staticInfoJson);
    EXPECT_EQ(ret, nullptr);
}

/*
 * @tc.name: GetLatestStaticInfoJson_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetLatestStaticInfoJson_002, TestSize.Level1)
{
    cJSON *staticInfoJson = cJSON_CreateObject();
    cJSON *ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetLatestStaticInfoJson(staticInfoJson);
    EXPECT_EQ(ret, nullptr);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoJsonByVersion_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoJsonByVersion_001, TestSize.Level1)
{
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "1.0";
    cJSON *ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfoJsonByVersion(staticInfoJson, staticVersion);
    EXPECT_EQ(ret, nullptr);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoJsonByVersion_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoJsonByVersion_002, TestSize.Level1)
{
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "";
    cJSON *ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfoJsonByVersion(staticInfoJson, staticVersion);
    EXPECT_EQ(ret, nullptr);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoJsonByVersion_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoJsonByVersion_003, TestSize.Level1)
{
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "1.0";
    cJSON_AddItemToObject(staticInfoJson, "StaticInfo", cJSON_CreateArray());
    cJSON *ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfoJsonByVersion(staticInfoJson, staticVersion);
    EXPECT_EQ(ret, nullptr);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticInfoJsonByVersion_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticInfoJsonByVersion_004, TestSize.Level1)
{
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticVersion = "1.0";
    cJSON *staticInfos = cJSON_CreateArray();
    cJSON_AddItemToObject(staticInfoJson, "StaticInfo", staticInfos);
    cJSON *ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticInfoJsonByVersion(staticInfoJson, staticVersion);
    EXPECT_EQ(ret, nullptr);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GetStaticVersion_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticVersion_001, TestSize.Level1)
{
    cJSON *lastStaticJson = nullptr;
    std::string staticVersion = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticVersion(lastStaticJson, staticVersion);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
}

/*
 * @tc.name: GetStaticVersion_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticVersion_002, TestSize.Level1)
{
    cJSON *lastStaticJson = cJSON_CreateObject();
    cJSON *dpVersionJson = cJSON_CreateString("1.0");
    cJSON_AddItemToObject(lastStaticJson, "dpVersion", dpVersionJson);
    std::string staticVersion = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticVersion(lastStaticJson, staticVersion);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
    cJSON_Delete(lastStaticJson);
}

/*
 * @tc.name: GenerateStaticProfiles_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GenerateStaticProfiles_001, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GenerateStaticProfiles("", staticCapability,
        staticInfoJson, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GenerateStaticProfiles_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GenerateStaticProfiles_002, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string longDeviceId(MAX_STRING_LEN + 1, 'a');
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GenerateStaticProfiles(longDeviceId, staticCapability,
        staticInfoJson, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: GenerateStaticProfiles_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GenerateStaticProfiles_003, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    std::string staticCapability = EMPTY_STRING;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GenerateStaticProfiles(deviceId, staticCapability,
        nullptr, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
}

/*
 * @tc.name: GenerateStaticProfiles_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GenerateStaticProfiles_004, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    cJSON *staticInfoJson = cJSON_CreateObject();
    std::string staticCapability = EMPTY_STRING;
    cJSON_AddItemToObject(staticInfoJson, ABILITY_KEY.c_str(), cJSON_CreateString("not an array"));
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GenerateStaticProfiles(deviceId, staticCapability,
        staticInfoJson, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
    cJSON_Delete(staticInfoJson);
}

/*
 * @tc.name: LoadStaticInfo_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticInfo_001, TestSize.Level1)
{
    std::string staticCapability = EMPTY_STRING;
    std::string staticVersion = "";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadStaticInfo(staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadStaticInfo_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticInfo_002, TestSize.Level1)
{
    std::string staticCapability(MAX_STRING_LEN + 1, 'a');
    std::string staticVersion = "";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadStaticInfo(staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

#ifdef DEVICE_PROFILE_SWITCH_STATIC_ENABLE
/*
 * @tc.name: LoadStaticInfo_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticInfo_003, TestSize.Level1)
{
    std::string staticCapability = "11";
    std::string staticVersion = "";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadStaticInfo(staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/*
 * @tc.name: LoadStaticInfo_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticInfo_004, TestSize.Level1)
{
    std::string staticCapability = "11";
    std::string staticVersion = "";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().LoadStaticInfo(staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
}
#endif // DEVICE_PROFILE_SWITCH_STATIC_ENABLE

/*
 * @tc.name: LoadStaticProfiles_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticProfiles_001, TestSize.Level1)
{
    std::string deviceId = "";
    std::string staticCapability = "staticCapability";
    std::string staticVersion = "staticVersion";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().LoadStaticProfiles(deviceId, staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadStaticProfiles_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticProfiles_002, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string staticCapability = EMPTY_STRING;
    std::string staticVersion = "staticVersion";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().LoadStaticProfiles(deviceId, staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/*
 * @tc.name: LoadStaticProfiles_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticProfiles_003, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string staticCapability = "staticCapability";
    std::string staticVersion = "";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().LoadStaticProfiles(deviceId, staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

#ifdef DEVICE_PROFILE_SWITCH_STATIC_ENABLE
/*
 * @tc.name: LoadStaticProfiles_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, LoadStaticProfiles_004, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string staticCapability = "staticCapability";
    std::string staticVersion = "staticVersion";
    std::unordered_map<std::string, CharacteristicProfile> charProfiles;
    int32_t ret = OHOS::DistributedDeviceProfile::StaticCapabilityLoader::
        GetInstance().LoadStaticProfiles(deviceId, staticCapability, staticVersion, charProfiles);
    EXPECT_EQ(ret, DP_GET_STATIC_INFO_FAIL);
}
#endif // DEVICE_PROFILE_SWITCH_STATIC_ENABLE

/*
 * @tc.name: InitStaticCapability_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, InitStaticCapability_001, TestSize.Level1)
{
    int32_t size = 2;
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().InitStaticCapability(size, staticCapability);
    EXPECT_EQ(staticCapability, "00");
}

/*
 * @tc.name: SetStaticCapability_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapability_001, TestSize.Level1)
{
    const cJSON *staticCapabilityItems = cJSON_CreateString("NotJsonArray");
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapability(staticCapabilityItems, staticCapability);
    EXPECT_EQ(staticCapability, "");
}

/*
 * @tc.name: SetStaticCapability_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapability_002, TestSize.Level1)
{
    cJSON *staticCapabilityItems = cJSON_CreateArray();
    cJSON *item = cJSON_CreateString("NotObject");
    std::string staticCapability = EMPTY_STRING;
    cJSON_AddItemToArray(staticCapabilityItems, item);
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapability(staticCapabilityItems, staticCapability);
    EXPECT_EQ(staticCapability, "");
    cJSON_Delete(staticCapabilityItems);
}

/*
 * @tc.name: SetStaticCapabilityFlag_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapabilityFlag_001, TestSize.Level1)
{
    std::string handlerName = "";
    std::string handlerLoc = "loc";
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapabilityFlag(handlerName, handlerLoc, staticCapability);
    EXPECT_EQ(staticCapability, "");
}

/*
 * @tc.name: SetStaticCapabilityFlag_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapabilityFlag_002, TestSize.Level1)
{
    std::string handlerName(MAX_STRING_LEN + 1, 'a');
    std::string handlerLoc = "loc";
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapabilityFlag(handlerName, handlerLoc, staticCapability);
    EXPECT_EQ(staticCapability, "");
}

/*
 * @tc.name: SetStaticCapabilityFlag_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapabilityFlag_003, TestSize.Level1)
{
    std::string handlerName = "name";
    std::string handlerLoc = "";
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapabilityFlag(handlerName, handlerLoc, staticCapability);
    EXPECT_EQ(staticCapability, "");
}

/*
 * @tc.name: SetStaticCapabilityFlag_004
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapabilityFlag_004, TestSize.Level1)
{
    std::string handlerName = "name";
    std::string handlerLoc(MAX_STRING_LEN + 1, 'a');
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapabilityFlag(handlerName, handlerLoc, staticCapability);
    EXPECT_EQ(staticCapability, "");
}

/*
 * @tc.name: SetStaticCapabilityFlag_005
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, SetStaticCapabilityFlag_005, TestSize.Level1)
{
    std::string handlerName = "name";
    std::string handlerLoc = "handlerLoc";
    std::string staticCapability = EMPTY_STRING;
    OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().SetStaticCapabilityFlag(handlerName, handlerLoc, staticCapability);
    EXPECT_EQ(staticCapability, "");
}

/*
 * @tc.name: GetStaticCapabilityValue_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticCapabilityValue_001, TestSize.Level1)
{
    std::string handlerLoc = "libpasteboard_framework.z.so";
    bool ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticCapabilityValue(handlerLoc);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: GetStaticCapabilityValue_002
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticCapabilityValue_002, TestSize.Level1)
{
    std::string handlerLoc = "libdistributed_sdk.z.so";
    bool ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticCapabilityValue(handlerLoc);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: GetStaticCapabilityValue_003
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, GetStaticCapabilityValue_003, TestSize.Level1)
{
    std::string handlerLoc = "aaa.z.so";
    bool ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().GetStaticCapabilityValue(handlerLoc);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: UnInit_001
 * @tc.desc: Normal testCase of StaticCapabilityLoaderTest
 * @tc.type: FUNC
 */
HWTEST_F(StaticCapabilityLoaderTest, UnInit_001, TestSize.Level1)
{
    int32_t ret = OHOS::DistributedDeviceProfile::
        StaticCapabilityLoader::GetInstance().UnInit();
    EXPECT_EQ(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
