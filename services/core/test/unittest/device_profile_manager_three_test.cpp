/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include <string>
#include <vector>
#include <new>
#include "gtest/gtest.h"
#include "refbase.h"
#include "iremote_stub.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_enums.h"
#include "device_profile.h"
#include "service_profile.h"
#include "content_sensor_manager_utils.h"
#include "characteristic_profile.h"
#include "i_sync_completed_callback.h"
#include "sync_completed_callback_stub.h"
#include "device_profile_manager.h"
#include "kv_adapter.h"
#include "profile_cache.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const int32_t PERMS_NUM = 2;
}
using namespace testing::ext;
using namespace std;

class DeviceProfileManagerThreeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DeviceProfileManagerThreeTest::SetUpTestCase(void) {
}

void DeviceProfileManagerThreeTest::TearDownTestCase(void) {
}

void DeviceProfileManagerThreeTest::SetUp()
{
    const char *perms[PERMS_NUM] = {
        "ohos.permission.DISTRIBUTED_DATASYNC",
        "ohos.permission.DISTRIBUTED_SOFTBUS_CENTER"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMS_NUM,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "deviceprofile",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

void DeviceProfileManagerThreeTest::TearDown() {
}

class SyncCallbackThree : public SyncCompletedCallbackStub {
public:
    void OnSyncCompleted(const map<string, SyncStatus>& syncResults) {
    }
};

/**
 * @tc.name: InitThree001
 * @tc.desc: Init succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, InitThree001, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().Init();
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: InitThree002
 * @tc.desc: Init succeed with different device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, InitThree002, TestSize.Level1)
{
    int32_t ret = DeviceProfileManager::GetInstance().Init();
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: InitThree003
 * @tc.desc: Init with first load.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, InitThree003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    int32_t ret = DeviceProfileManager::GetInstance().Init();
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: UnInitThree001
 * @tc.desc: UnInit succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, UnInitThree001, TestSize.Level1)
{
    int32_t ret = DeviceProfileManager::GetInstance().UnInit();
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: UnInitThree002
 * @tc.desc: deviceProfileStore_ is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, UnInitThree002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().UnInit();
    EXPECT_NE(ret, DP_SUCCESS);
}

/**
 * @tc.name: ReInitThree001
 * @tc.desc: ReInit succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, ReInitThree001, TestSize.Level1)
{
    int32_t ret = DeviceProfileManager::GetInstance().ReInit();
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: ReInitThree002
 * @tc.desc: ReInit with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, ReInitThree002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().ReInit();
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutDeviceProfileThree001
 * @tc.desc: PutDeviceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutDeviceProfileThree001, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "anything_three_1";
    deviceProfile.SetDeviceId("anything_three_1");
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);

    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutDeviceProfileThree002
 * @tc.desc: PutDeviceProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutDeviceProfileThree002, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("");
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);

    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutDeviceProfileThree003
 * @tc.desc: PutDeviceProfile with existing profile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutDeviceProfileThree003, TestSize.Level1)
{
    DeviceProfile deviceProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "anything_three_3";
    deviceProfile1.SetDeviceId("anything_three_3");
    deviceProfile1.SetDeviceName("anything");
    deviceProfile1.SetManufactureName("anything");
    deviceProfile1.SetDeviceModel("anything");
    deviceProfile1.SetStorageCapability(1);
    deviceProfile1.SetOsSysCap("anything");
    deviceProfile1.SetOsApiLevel(1);
    deviceProfile1.SetOsVersion("anything");
    deviceProfile1.SetOsType(1);

    DeviceProfile deviceProfile2;
    deviceProfile2.SetDeviceId("anything_three_3");
    deviceProfile2.SetDeviceName("anything");
    deviceProfile2.SetManufactureName("anything");
    deviceProfile2.SetDeviceModel("anything");
    deviceProfile2.SetStorageCapability(1);
    deviceProfile2.SetOsSysCap("anything");
    deviceProfile2.SetOsApiLevel(1);
    deviceProfile2.SetOsVersion("anything");
    deviceProfile2.SetOsType(1);

    DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile1);
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile2);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutDeviceProfileThree004
 * @tc.desc: PutDeviceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutDeviceProfileThree004, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "anything_three_4";
    deviceProfile.SetDeviceId("anything_three_4");
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);

    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_NE(ret, DP_SUCCESS);
}

/**
 * @tc.name: PutDeviceProfileThree005
 * @tc.desc: PutDeviceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutDeviceProfileThree005, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "anything_three_5";
    deviceProfile.SetDeviceId("anything_three_5");
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: PutDeviceProfileThree006
 * @tc.desc: PutDeviceProfile with different device types.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutDeviceProfileThree006, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "anything_three_6";
    deviceProfile.SetDeviceId("anything_three_6");
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileThree001
 * @tc.desc: PutServiceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThree1";
    serviceProfile.SetDeviceId("deviceIdThree1");
    serviceProfile.SetServiceName("serviceNameThree1");
    serviceProfile.SetServiceType("serviceTypeThree1");

    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileThree002
 * @tc.desc: PutServiceProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree002, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("");
    serviceProfile.SetServiceName("serviceNameThree2");
    serviceProfile.SetServiceType("serviceTypeThree2");

    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileThree003
 * @tc.desc: PutServiceProfile with existing profile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree003, TestSize.Level1)
{
    ServiceProfile serviceProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThree3";
    serviceProfile1.SetDeviceId("deviceIdThree3");
    serviceProfile1.SetServiceName("serviceNameThree3");
    serviceProfile1.SetServiceType("serviceTypeThree3");

    ServiceProfile serviceProfile2;
    serviceProfile2.SetDeviceId("deviceIdThree3");
    serviceProfile2.SetServiceName("serviceNameThree3");
    serviceProfile2.SetServiceType("serviceTypeThree3");

    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile1);
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile2);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileThree004
 * @tc.desc: PutServiceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree004, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("deviceIdThree4");
    serviceProfile.SetServiceName("serviceNameThree4");
    serviceProfile.SetServiceType("serviceTypeThree4");

    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileThree005
 * @tc.desc: PutServiceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree005, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThree5";
    serviceProfile.SetDeviceId("deviceIdThree5");
    serviceProfile.SetServiceName("serviceNameThree5");
    serviceProfile.SetServiceType("serviceTypeThree5");

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: PutServiceProfileThree006
 * @tc.desc: PutServiceProfile with isFirst true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree006, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThree6";
    serviceProfile.SetDeviceId("deviceIdThree6");
    serviceProfile.SetServiceName("serviceNameThree6");
    serviceProfile.SetServiceType("serviceTypeThree6");
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileThree007
 * @tc.desc: PutServiceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileThree007, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThree7";
    serviceProfile.SetDeviceId("deviceIdThree7");
    serviceProfile.SetServiceName("serviceNameThree7");
    serviceProfile.SetServiceType("serviceTypeThree7");
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileBatchThree001
 * @tc.desc: PutServiceProfileBatch succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileBatchThree001, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    ServiceProfile serviceProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeBatch1";
    serviceProfile1.SetDeviceId("deviceIdThreeBatch1");
    serviceProfile1.SetServiceName("serviceNameThreeBatch1");
    serviceProfile1.SetServiceType("serviceTypeThreeBatch1");
    serviceProfiles.push_back(serviceProfile1);

    ServiceProfile serviceProfile2;
    serviceProfile2.SetDeviceId("deviceIdThreeBatch2");
    serviceProfile2.SetServiceName("serviceNameThreeBatch2");
    serviceProfile2.SetServiceType("serviceTypeThreeBatch2");
    serviceProfiles.push_back(serviceProfile2);

    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    ret = DeviceProfileManager::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutServiceProfileBatchThree002
 * @tc.desc: PutServiceProfileBatch with invalid first profile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutServiceProfileBatchThree002, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    ServiceProfile serviceProfile1;
    serviceProfile1.SetDeviceId("");
    serviceProfile1.SetServiceName("serviceNameThree");
    serviceProfile1.SetServiceType("serviceTypeThree");
    serviceProfiles.push_back(serviceProfile1);

    ServiceProfile serviceProfile4;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeBatch4";
    serviceProfile4.SetDeviceId("deviceIdThreeBatch4");
    serviceProfile4.SetServiceName("serviceNameThreeBatch4");
    serviceProfile4.SetServiceType("serviceTypeThreeBatch4");
    serviceProfiles.push_back(serviceProfile4);

    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfileThree001
 * @tc.desc: PutCharacteristicProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileThree001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeChar1";
    charProfile.SetDeviceId("deviceIdThreeChar1");
    charProfile.SetServiceName("serviceNameThreeChar1");
    charProfile.SetCharacteristicKey("characteristicKeyThree1");
    charProfile.SetCharacteristicValue("characteristicValueThree1");

    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfileThree002
 * @tc.desc: PutCharacteristicProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileThree002, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("");
    charProfile.SetServiceName("serviceNameThreeChar2");
    charProfile.SetCharacteristicKey("characteristicKeyThree2");
    charProfile.SetCharacteristicValue("characteristicValueThree2");

    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfileThree003
 * @tc.desc: PutCharacteristicProfile with existing profile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileThree003, TestSize.Level1)
{
    CharacteristicProfile charProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeChar3";
    charProfile1.SetDeviceId("deviceIdThreeChar3");
    charProfile1.SetServiceName("serviceNameThreeChar3");
    charProfile1.SetCharacteristicKey("characteristicKeyThree3");
    charProfile1.SetCharacteristicValue("characteristicValueThree3");

    CharacteristicProfile charProfile2;
    charProfile2.SetDeviceId("deviceIdThreeChar3");
    charProfile2.SetServiceName("serviceNameThreeChar3");
    charProfile2.SetCharacteristicKey("characteristicKeyThree3");
    charProfile2.SetCharacteristicValue("characteristicValueThree3");

    DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile1);
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile2);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfileThree004
 * @tc.desc: PutCharacteristicProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileThree004, TestSize.Level1)
{
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeChar4";
    CharacteristicProfile charProfile10;
    charProfile10.SetDeviceId("deviceIdThreeChar4");
    charProfile10.SetServiceName("serviceNameThreeChar4");
    charProfile10.SetCharacteristicKey("characteristicKeyThree4");
    charProfile10.SetCharacteristicValue("characteristicValueThree4");

    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile10);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfileThree005
 * @tc.desc: PutCharacteristicProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileThree005, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeChar5";
    charProfile.SetDeviceId("deviceIdThreeChar5");
    charProfile.SetServiceName("serviceNameThreeChar5");
    charProfile.SetCharacteristicKey("characteristicKeyThree5");
    charProfile.SetCharacteristicValue("characteristicValueThree5");

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: PutCharacteristicProfileThree006
 * @tc.desc: PutCharacteristicProfile with isFirst true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileThree006, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeChar6";
    charProfile.SetDeviceId("deviceIdThreeChar6");
    charProfile.SetServiceName("serviceNameThreeChar6");
    charProfile.SetCharacteristicKey("characteristicKeyThree6");
    charProfile.SetCharacteristicValue("characteristicValueThree6");
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: PutCharacteristicProfileBatchThree001
 * @tc.desc: PutCharacteristicProfileBatch succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileBatchThree001, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    CharacteristicProfile charProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeCharBatch1";
    charProfile1.SetDeviceId("deviceIdThreeCharBatch1");
    charProfile1.SetServiceName("serviceNameThreeCharBatch1");
    charProfile1.SetCharacteristicKey("characteristicKeyThreeBatch1");
    charProfile1.SetCharacteristicValue("characteristicValueThreeBatch1");
    charProfiles.push_back(charProfile1);

    CharacteristicProfile charProfile2;
    charProfile2.SetDeviceId("deviceIdThreeCharBatch2");
    charProfile2.SetServiceName("serviceNameThreeCharBatch2");
    charProfile2.SetCharacteristicKey("characteristicKeyThreeBatch2");
    charProfile2.SetCharacteristicValue("characteristicValueThreeBatch2");
    charProfiles.push_back(charProfile2);

    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfileBatchThree002
 * @tc.desc: PutCharacteristicProfileBatch with invalid first profile.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, PutCharacteristicProfileBatchThree002, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    CharacteristicProfile charProfile1;
    charProfile1.SetDeviceId("");
    charProfile1.SetServiceName("serviceNameThreeCharBatch");
    charProfile1.SetCharacteristicKey("characteristicKeyThreeCharBatch");
    charProfile1.SetCharacteristicValue("characteristicValueThreeCharBatch");
    charProfiles.push_back(charProfile1);

    CharacteristicProfile charProfile4;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeCharBatch4";
    charProfile4.SetDeviceId("deviceIdThreeCharBatch4");
    charProfile4.SetServiceName("serviceNameThreeCharBatch4");
    charProfile4.SetCharacteristicKey("characteristicKeyThreeCharBatch4");
    charProfile4.SetCharacteristicValue("characteristicValueThreeCharBatch4");
    charProfiles.push_back(charProfile4);

    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetDeviceProfileThree001
 * @tc.desc: GetDeviceProfile succeed from cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetDeviceProfileThree001, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeGet1";
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    deviceProfile.SetDeviceId(deviceId);
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);

    DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);

    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    outDeviceProfile.SetDeviceId(deviceId);
    string outDeviceId = outDeviceProfile.GetDeviceId();
    outDeviceProfile.GetDeviceName();
    outDeviceProfile.GetManufactureName();
    outDeviceProfile.GetDeviceModel();
    outDeviceProfile.GetStorageCapability();
    outDeviceProfile.GetOsSysCap();
    outDeviceProfile.GetOsApiLevel();
    outDeviceProfile.GetOsVersion();
    outDeviceProfile.GetOsType();
    EXPECT_NE(outDeviceId, "");
}

/**
 * @tc.name: GetDeviceProfileThree002
 * @tc.desc: GetDeviceProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetDeviceProfileThree002, TestSize.Level1)
{
    string deviceId = "";
    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetDeviceProfileThree003
 * @tc.desc: GetDeviceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetDeviceProfileThree003, TestSize.Level1)
{
    string deviceId = "anythingThree12";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetDeviceProfileThree004
 * @tc.desc: GetDeviceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetDeviceProfileThree004, TestSize.Level1)
{
    string deviceId = "#anythingThree13";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: GetServiceProfileThree001
 * @tc.desc: GetServiceProfile succeed from cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetServiceProfileThree001, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    ServiceProfile serviceProfile5;
    serviceProfile5.SetDeviceId(deviceId);
    serviceProfile5.SetServiceName("serviceNameThreeGet5");
    serviceProfile5.SetServiceType("serviceTypeThreeGet5");
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile5);

    string serviceName = "serviceNameThreeGet5";
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    string outDeviceId = outServiceProfile.GetDeviceId();
    outServiceProfile.GetServiceName();
    outServiceProfile.GetServiceType();
    EXPECT_NE(outDeviceId, "");
}

/**
 * @tc.name: GetServiceProfileThree002
 * @tc.desc: GetServiceProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetServiceProfileThree002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceNameThree";
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    deviceId = "deviceIdThreeGet";
    serviceName = "";
    ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetServiceProfileThree003
 * @tc.desc: GetServiceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetServiceProfileThree003, TestSize.Level1)
{
    string deviceId = "deviceIdThreeGet12";
    string serviceName = "serviceNameThreeGet12";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetServiceProfileThree004
 * @tc.desc: GetServiceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetServiceProfileThree004, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    string serviceName = "serviceNameThreeGet13";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: GetCharacteristicProfileThree001
 * @tc.desc: GetCharacteristicProfile succeed from cache.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetCharacteristicProfileThree001, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    CharacteristicProfile charProfile5;
    charProfile5.SetDeviceId(deviceId);
    charProfile5.SetServiceName("serviceNameThreeGetChar5");
    charProfile5.SetCharacteristicKey("characteristicKeyThreeGet5");
    charProfile5.SetCharacteristicValue("characteristicValueThreeGet5");
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile5);

    string serviceName = "serviceNameThreeGetChar5";
    string characteristicKey = "characteristicKeyThreeGet5";
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    string outDeviceId = outCharProfile.GetDeviceId();
    outCharProfile.GetServiceName();
    outCharProfile.GetCharacteristicKey();
    outCharProfile.GetCharacteristicValue();
    EXPECT_NE(outDeviceId, "");
}

/**
 * @tc.name: GetCharacteristicProfileThree002
 * @tc.desc: GetCharacteristicProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetCharacteristicProfileThree002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceNameThreeGetChar";
    string characteristicKey = "characteristicKeyThreeGet";
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    deviceId = "deviceIdThreeGetChar";
    serviceName = "serviceNameThreeGetChar";
    characteristicKey = "";
    ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetCharacteristicProfileThree003
 * @tc.desc: GetCharacteristicProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetCharacteristicProfileThree003, TestSize.Level1)
{
    string deviceId = "deviceIdThreeGetChar12";
    string serviceName = "serviceNameThreeGetChar12";
    string characteristicKey = "characteristicKeyThreeGetChar12";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetCharacteristicProfileThree004
 * @tc.desc: GetCharacteristicProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetCharacteristicProfileThree004, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    string serviceName = "serviceNameThreeGetChar13";
    string characteristicKey = "characteristicKeyThreeGetChar13";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: DeleteServiceProfileThree001
 * @tc.desc: DeleteServiceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteServiceProfileThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile6;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeDel6";
    serviceProfile6.SetDeviceId("deviceIdThreeDel6");
    serviceProfile6.SetServiceName("serviceNameThreeDel6");
    serviceProfile6.SetServiceType("serviceTypeThreeDel6");
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile6);

    string deviceId = "deviceIdThreeDel6";
    string serviceName = "serviceNameThreeDel6";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteServiceProfileThree002
 * @tc.desc: DeleteServiceProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteServiceProfileThree002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceNameThreeDel";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    deviceId = "deviceIdThreeDel";
    serviceName = "";
    ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteServiceProfileThree003
 * @tc.desc: DeleteServiceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteServiceProfileThree003, TestSize.Level1)
{
    string deviceId = "deviceIdThreeDel14";
    string serviceName = "serviceNameThreeDel14";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteServiceProfileThree004
 * @tc.desc: DeleteServiceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteServiceProfileThree004, TestSize.Level1)
{
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeDel15";
    string deviceId = "deviceIdThreeDel15";
    string serviceName = "serviceNameThreeDel15";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: SetIsMultiUserThree001
 * @tc.desc: SetIsMultiUser Success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SetIsMultiUserThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile7;
    bool isMultiUser = true;
    serviceProfile7.SetIsMultiUser(isMultiUser);
    EXPECT_NE(isMultiUser, false);
}

/**
 * @tc.name: IsMultiUserThree001
 * @tc.desc: IsMultiUser Success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsMultiUserThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile8;
    bool isMultiUser = true;
    serviceProfile8.SetIsMultiUser(isMultiUser);
    bool ret = serviceProfile8.IsMultiUser();
    EXPECT_NE(ret, false);
}

/**
 * @tc.name: SetUserIdThree001
 * @tc.desc: SetUserId Success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SetUserIdThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile9;
    int32_t userId = 1;
    serviceProfile9.SetUserId(userId);
    EXPECT_NE(userId, 0);
}

/**
 * @tc.name: GetUserIdThree001
 * @tc.desc: GetUserId Success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetUserIdThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile9;
    int32_t userId = 1;
    serviceProfile9.SetUserId(userId);
    int32_t outUserId = serviceProfile9.GetUserId();
    EXPECT_NE(outUserId, userId - 1);
}

/**
 * @tc.name: DeleteCharacteristicProfileThree001
 * @tc.desc: DeleteCharacteristicProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteCharacteristicProfileThree001, TestSize.Level1)
{
    CharacteristicProfile charProfile6;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeDelChar6";
    charProfile6.SetDeviceId("deviceIdThreeDelChar6");
    charProfile6.SetServiceName("serviceNameThreeDelChar6");
    charProfile6.SetCharacteristicKey("characteristicKeyThreeDel6");
    charProfile6.SetCharacteristicValue("characteristicValueThreeDel6");
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile6);

    string deviceId = "deviceIdThreeDelChar6";
    string serviceName = "serviceNameThreeDelChar6";
    string characteristicKey = "characteristicKeyThreeDel6";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteCharacteristicProfileThree002
 * @tc.desc: DeleteCharacteristicProfile with empty device id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteCharacteristicProfileThree002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceNameThreeDelChar";
    string characteristicKey = "characteristicKeyThreeDelChar";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);

    deviceId = "deviceIdThreeDelChar";
    serviceName = "serviceNameThreeDelChar";
    characteristicKey = "";
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteCharacteristicProfileThree003
 * @tc.desc: DeleteCharacteristicProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteCharacteristicProfileThree003, TestSize.Level1)
{
    string deviceId = "deviceIdThreeDelChar14";
    string serviceName = "serviceNameThreeDelChar14";
    string characteristicKey = "characteristicKeyThreeDelChar14";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteCharacteristicProfileThree004
 * @tc.desc: DeleteCharacteristicProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteCharacteristicProfileThree004, TestSize.Level1)
{
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceIdThreeDelChar15";
    string deviceId = "deviceIdThreeDelChar15";
    string serviceName = "serviceNameThreeDelChar15";
    string characteristicKey = "characteristicKeyThreeDelChar15";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: GetAllDeviceProfileThree001
 * @tc.desc: GetAllDeviceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllDeviceProfileThree001, TestSize.Level1)
{
    vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetAllDeviceProfileThree002
 * @tc.desc: GetAllDeviceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllDeviceProfileThree002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetAllDeviceProfileThree003
 * @tc.desc: GetAllDeviceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllDeviceProfileThree003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: GetAllServiceProfileThree001
 * @tc.desc: GetAllServiceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllServiceProfileThree001, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetAllServiceProfileThree002
 * @tc.desc: GetAllServiceProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllServiceProfileThree002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetAllServiceProfileThree003
 * @tc.desc: GetAllServiceProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllServiceProfileThree003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: GetAllCharacteristicProfileThree001
 * @tc.desc: GetAllCharacteristicProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllCharacteristicProfileThree001, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetAllCharacteristicProfileThree002
 * @tc.desc: GetAllCharacteristicProfile with nullptr store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllCharacteristicProfileThree002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: GetAllCharacteristicProfileThree003
 * @tc.desc: GetAllCharacteristicProfile after uninit store.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetAllCharacteristicProfileThree003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
 * @tc.name: SyncDeviceProfileThree001
 * @tc.desc: SyncDeviceProfile with invalid params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SyncDeviceProfileThree001, TestSize.Level1)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    OHOS::sptr<OHOS::IRemoteObject> syncCb = nullptr;

    syncOptions.AddDevice("deviceIdThreeSync1");
    syncOptions.AddDevice("deviceIdThreeSync2");
    syncOptions.SetSyncMode(SyncMode::MIN);

    int32_t errCode = DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: SyncDeviceProfileThree002
 * @tc.desc: SyncDeviceProfile with MAX mode.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SyncDeviceProfileThree002, TestSize.Level1)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    OHOS::sptr<OHOS::IRemoteObject> syncCb = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallbackThree());

    syncOptions.AddDevice("deviceIdThreeSync3");
    syncOptions.AddDevice("deviceIdThreeSync4");
    syncOptions.SetSyncMode(SyncMode::MAX);

    int32_t errCode = DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_NE(errCode, DP_SUCCESS);
}

/**
 * @tc.name: DeviceProfileMarshallingThree001
 * @tc.desc: DeviceProfile Marshalling and UnMarshalling succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeviceProfileMarshallingThree001, TestSize.Level1)
{
    OHOS::MessageParcel data;
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("anythingThree");
    deviceProfile.SetDeviceName("anythingThree");
    deviceProfile.SetManufactureName("anythingThree");
    deviceProfile.SetDeviceModel("anythingThree");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anythingThree");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anythingThree");
    deviceProfile.SetOsType(1);

    bool res1 = deviceProfile.Marshalling(data);
    EXPECT_NE(res1, false);

    bool res2 = deviceProfile.UnMarshalling(data);
    EXPECT_NE(res2, false);
}

/**
 * @tc.name: DeviceProfileOperatorThree001
 * @tc.desc: DeviceProfileOperator true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeviceProfileOperatorThree001, TestSize.Level1)
{
    DeviceProfile deviceProfile1;
    deviceProfile1.SetDeviceId("anythingThree1");
    deviceProfile1.SetDeviceName("anythingThree1");
    deviceProfile1.SetManufactureName("anythingThree1");
    deviceProfile1.SetDeviceModel("anythingThree1");
    deviceProfile1.SetStorageCapability(1);
    deviceProfile1.SetOsSysCap("anythingThree1");
    deviceProfile1.SetOsApiLevel(1);
    deviceProfile1.SetOsVersion("anythingThree1");
    deviceProfile1.SetOsType(1);

    DeviceProfile deviceProfile2;
    deviceProfile2.SetDeviceId("anythingThree2");
    deviceProfile2.SetDeviceName("anythingThree2");
    deviceProfile2.SetManufactureName("anythingThree2");
    deviceProfile2.SetDeviceModel("anythingThree2");
    deviceProfile2.SetStorageCapability(1);
    deviceProfile2.SetOsSysCap("anythingThree2");
    deviceProfile2.SetOsApiLevel(1);
    deviceProfile2.SetOsVersion("anythingThree2");
    deviceProfile2.SetOsType(1);

    bool res = deviceProfile1 != deviceProfile2;
    EXPECT_NE(res, false);
}

/**
 * @tc.name: DeviceProfileDumpThree001
 * @tc.desc: DeviceProfileDump succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeviceProfileDumpThree001, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("anythingThree");
    deviceProfile.SetDeviceName("anythingThree");
    deviceProfile.SetManufactureName("anythingThree");
    deviceProfile.SetDeviceModel("anythingThree");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anythingThree");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anythingThree");
    deviceProfile.SetOsType(1);

    string strJson = deviceProfile.dump();
    char fistChar = strJson.front();
    char lastChar = strJson.back();
    EXPECT_NE(fistChar, '[');
    EXPECT_NE(lastChar, ']');
}

/**
 * @tc.name: ServiceProfileConstructorThree001
 * @tc.desc: ServiceProfileConstructor succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, ServiceProfileConstructorThree001, TestSize.Level1)
{
    ServiceProfile serviceProfile = ServiceProfile("deviceIdThree", "serviceNameThree", "serviceTypeThree");
    EXPECT_NE(serviceProfile.GetDeviceId(), "");
}

/**
 * @tc.name: LoadDpSyncAdapterThree001
 * @tc.desc: LoadDpSyncAdapter first branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, LoadDpSyncAdapterThree001, TestSize.Level1)
{
    char path[PATH_MAX + 1] = {0x00};
    std::string soName = "/system/lib/libdeviceprofileadapter.z.so";
    bool ret = false;
    if ((soName.length() == 0) || (soName.length() > PATH_MAX) || (realpath(soName.c_str(), path) == nullptr)) {
        ret = true;
    } else {
        DeviceProfileManager::GetInstance().isAdapterSoLoaded_ = true;
        ret = DeviceProfileManager::GetInstance().LoadDpSyncAdapter();
    }
    EXPECT_NE(ret, false);
}

/**
 * @tc.name: GetInKvDBThree001
 * @tc.desc: GetDeviceProfile,GetServiceProfile, GetCharacteristicProfile succeed, in KV DB.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetInKvDBThree001, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId(deviceId);
    deviceProfile.SetDeviceName("GetInKvDBThree001_DeviceName");
    deviceProfile.SetManufactureName("GetInKvDBThree001_ManufactureName");
    deviceProfile.SetDeviceModel("GetInKvDBThree001_DeviceModel");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("GetInKvDBThree001_OsSysCap");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("GetInKvDBThree001_OsVersion");
    deviceProfile.SetOsType(1);
    DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);

    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(deviceId);
    serviceProfile.SetServiceName("GetInKvDBThree001_ServiceName");
    serviceProfile.SetServiceType("GetInKvDBThree001_ServiceType");
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);

    CharacteristicProfile charProfile;
    charProfile.SetDeviceId(deviceId);
    charProfile.SetServiceName("GetInKvDBThree001_ServiceName");
    charProfile.SetCharacteristicKey("GetInKvDBThree001_CharacteristicKey");
    charProfile.SetCharacteristicValue("GetInKvDBThree001_CharacteristicValue");
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);

    ProfileCache::GetInstance().DeleteDeviceProfile(deviceId);
    ProfileCache::GetInstance().DeleteServiceProfile("GetInKvDBThree001_DeviceId", "GetInKvDBThree001_ServiceName");
    ProfileCache::GetInstance().DeleteCharProfile("GetInKvDBThree001_DeviceId", "GetInKvDBThree001_ServiceName",
                                                            "GetInKvDBThree001_CharacteristicKey");

    DeviceProfile outDeviceProfile;
    int32_t ret1 = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_NE(ret1, DP_UPDATE_ACL_PROFILE_FAIL);

    string serviceName = "GetInKvDBThree001_ServiceName";
    ServiceProfile outServiceProfile;
    int32_t ret2 = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_NE(ret2, DP_UPDATE_ACL_PROFILE_FAIL);

    string characteristicKey = "GetInKvDBThree001_CharacteristicKey";
    CharacteristicProfile outCharProfile;
    int32_t ret3 = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
                                                                               characteristicKey, outCharProfile);
    EXPECT_NE(ret3, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: RunloadedFunctionThree001
 * @tc.desc: RunloadedFunction001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, RunloadedFunctionThree001, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().dpSyncAdapter_ = nullptr;
    OHOS::sptr<OHOS::IRemoteObject> syncCb = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallbackThree());
    const std::string& peerUdid = "peerUdidThree";
    const std::string& peerNetId = "peerNetIdThree";
    bool isP2p = false;
    int32_t ret = DeviceProfileManager::GetInstance().RunloadedFunction(peerUdid, peerNetId, syncCb, isP2p);
    EXPECT_NE(ret, DP_SUCCESS);
}

/**
 * @tc.name: RunloadedFunctionThree002
 * @tc.desc: RunloadedFunction002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, RunloadedFunctionThree002, TestSize.Level1)
{
    OHOS::sptr<OHOS::IRemoteObject> syncCb = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallbackThree());
    const std::string& peerUdid = "peerUdidThree";
    const std::string& peerNetId = "peerNetIdThree";
    bool isP2p = false;
    int32_t ret = DeviceProfileManager::GetInstance().RunloadedFunction(peerUdid, peerNetId, syncCb, isP2p);
    EXPECT_NE(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetInKvDBThree002
 * @tc.desc: GetInKvDBThree002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetInKvDBThree002, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId(deviceId);
    deviceProfile.SetDeviceName("GetInKvDBThree001_DeviceName2");
    deviceProfile.SetManufactureName("GetInKvDBThree001_ManufactureName2");
    deviceProfile.SetDeviceModel("GetInKvDBThree001_DeviceModel2");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("GetInKvDBThree001_OsSysCap2");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("GetInKvDBThree001_OsVersion2");
    deviceProfile.SetOsType(1);
    DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);

    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(deviceId);
    serviceProfile.SetServiceName("GetInKvDBThree001_ServiceName2");
    serviceProfile.SetServiceType("GetInKvDBThree001_ServiceType2");
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);

    CharacteristicProfile charProfile;
    charProfile.SetDeviceId(deviceId);
    charProfile.SetServiceName("GetInKvDBThree001_ServiceName2");
    charProfile.SetCharacteristicKey("GetInKvDBThree001_CharacteristicKey2");
    charProfile.SetCharacteristicValue("GetInKvDBThree001_CharacteristicValue2");
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);

    ProfileCache::GetInstance().DeleteDeviceProfile(deviceId);
    ProfileCache::GetInstance().DeleteServiceProfile("GetInKvDBThree001_DeviceId2", "GetInKvDBThree001_ServiceName");
    ProfileCache::GetInstance().DeleteCharProfile("GetInKvDBThree001_DeviceId2", "GetInKvDBThree001_ServiceName",
    "GetInKvDBThree001_CharacteristicKey2");

    DeviceProfile outDeviceProfile;
    DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);

    string serviceName = "GetInKvDBThree001_ServiceName2";
    ServiceProfile outServiceProfile;
    DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);

    string characteristicKey = "GetInKvDBThree001_CharacteristicKey2";
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
                                                                                characteristicKey, outCharProfile);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: HasTrustP2PRelationThree001
 * @tc.desc: param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, HasTrustP2PRelationThree001, TestSize.Level1)
{
    bool ret = DeviceProfileManager::GetInstance().HasTrustP2PRelation("", 100);
    EXPECT_NE(ret, true);
}

/**
 * @tc.name: HasTrustP2PRelationThree002
 * @tc.desc: HasTrustP2PRelation failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, HasTrustP2PRelationThree002, TestSize.Level1)
{
    bool ret = DeviceProfileManager::GetInstance().HasTrustP2PRelation("deviceIdThree", 100);
    EXPECT_NE(ret, true);
}

/**
 * @tc.name: IsSameAccountThree001
 * @tc.desc: param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsSameAccountThree001, TestSize.Level1)
{
    bool ret = DeviceProfileManager::GetInstance().IsSameAccount("", 100);
    EXPECT_NE(ret, true);
}

/**
 * @tc.name: IsSameAccountThree002
 * @tc.desc: GetAccessControlProfile failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsSameAccountThree002, TestSize.Level1)
{
    bool ret = DeviceProfileManager::GetInstance().IsSameAccount("deviceIdThree", 100);
    EXPECT_NE(ret, true);
}

/**
 * @tc.name: IsMultiUserValidThree001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsMultiUserValidThree001, TestSize.Level1)
{
    ServiceProfile profile("", "serviceNameThree", "serviceTypeThree");
    profile.SetIsMultiUser(false);
    profile.SetUserId(DEFAULT_USER_ID);

    int32_t result = DeviceProfileManager::GetInstance().IsMultiUserValid(profile);
    EXPECT_NE(result, DP_SUCCESS);
}

/**
 * @tc.name: IsMultiUserValidThree002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsMultiUserValidThree002, TestSize.Level1)
{
    ServiceProfile profile("deviceIdThree", "serviceNameThree", "serviceTypeThree");
    profile.SetIsMultiUser(true);
    profile.SetUserId(0);

    int32_t result = DeviceProfileManager::GetInstance().IsMultiUserValid(profile);
    EXPECT_NE(result, DP_SUCCESS);
}

/**
 * @tc.name: IsMultiUserValidThree003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsMultiUserValidThree003, TestSize.Level1)
{
    ServiceProfile profile("deviceIdThree", "serviceNameThree", "serviceTypeThree");
    profile.SetIsMultiUser(false);
    profile.SetUserId(DEFAULT_USER_ID + 1);

    int32_t result = DeviceProfileManager::GetInstance().IsMultiUserValid(profile);
    EXPECT_NE(result, DP_SUCCESS);
}

/**
 * @tc.name: IsMultiUserValidThree004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, IsMultiUserValidThree004, TestSize.Level1)
{
    ServiceProfile profile(ProfileCache::GetInstance().GetLocalUdid(), "serviceNameThree", "serviceTypeThree");
    profile.SetIsMultiUser(true);
    profile.SetUserId(333);

    int32_t result = DeviceProfileManager::GetInstance().IsMultiUserValid(profile);
    EXPECT_NE(result, DP_SUCCESS);
}

/**
 * @tc.name: SaveBatchByKeysThree001
 * @tc.desc: entries is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SaveBatchByKeysThree001, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    int32_t result = DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);
    EXPECT_NE(result, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: SaveBatchByKeysThree002
 * @tc.desc: succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SaveBatchByKeysThree002, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("keyThree1", "valueThree1"));
    int32_t result = DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);
    EXPECT_NE(result, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: SaveBatchByKeysThree003
 * @tc.desc: deviceProfileStore is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SaveBatchByKeysThree003, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("keyThree1", "valueThree1"));
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t result = DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);
    EXPECT_NE(result, DP_UPDATE_ACL_PROFILE_FAIL);
    DeviceProfileManager::GetInstance().FixDiffProfiles();
    DeviceProfileManager::GetInstance().dpSyncAdapter_ = nullptr;
    DeviceProfileManager::GetInstance().FixDiffProfiles();
    DeviceProfileManager::GetInstance().FixRemoteDataWhenPeerIsOHBase("remoteUdidThree", entries);
    DeviceProfileManager::GetInstance().FixRemoteDataWhenPeerIsNonOH("remoteUdidThree");
}

/**
 * @tc.name: GetProfilesByKeyPrefixThree001
 * @tc.desc: DP_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetProfilesByKeyPrefixThree001, TestSize.Level1)
{
    std::string udid = "";
    std::map<std::string, std::string> values;
    int32_t result = DeviceProfileManager::GetInstance().GetProfilesByKeyPrefix(udid, values);
    EXPECT_NE(result, DP_SUCCESS);
}

/**
 * @tc.name: GetProfilesByKeyPrefixThree002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetProfilesByKeyPrefixThree002, TestSize.Level1)
{
    std::string udid = "udidThree";
    std::map<std::string, std::string> values;
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t result = DeviceProfileManager::GetInstance().GetProfilesByKeyPrefix(udid, values);
    EXPECT_NE(result, DP_SUCCESS);
}

/**
 * @tc.name: DeleteRemovedUserDataThree001
 * @tc.desc: DeleteRemovedUserData001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteRemovedUserDataThree001, TestSize.Level1)
{
    int32_t userId = -1;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteRemovedUserData(userId);
    EXPECT_NE(ret, DP_SUCCESS);
}

/**
 * @tc.name: DeleteRemovedUserDataThree002
 * @tc.desc: DeleteRemovedUserData002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteRemovedUserDataThree002, TestSize.Level1)
{
    int32_t userId = 100001;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteRemovedUserData(userId);
    EXPECT_NE(ret, DP_SUCCESS);
}

/**
 * @tc.name: DeleteRemovedUserDataThree003
 * @tc.desc: DeleteRemovedUserData003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteRemovedUserDataThree003, TestSize.Level1)
{
    int32_t userId = 1;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteRemovedUserData(userId);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: DeleteRemovedUserDataThree005
 * @tc.desc: DeleteRemovedUserData005
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, DeleteRemovedUserDataThree005, TestSize.Level1)
{
    int32_t userId = 1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "localUdidThree";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteRemovedUserData(userId);
    EXPECT_NE(ret, DP_UPDATE_ACL_PROFILE_FAIL);
}

/**
 * @tc.name: SyncWithNotOHBasedDeviceThree001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, SyncWithNotOHBasedDeviceThree001, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().UnloadDpSyncAdapter();
    bool adapterAvailable = DeviceProfileManager::GetInstance().LoadDpSyncAdapter();
    DeviceProfileManager::GetInstance().UnloadDpSyncAdapter();
    const std::string callerDescriptor;
    sptr<IRemoteObject> syncCompletedCallback;
    const std::vector<std::tuple<std::string, std::string, bool>> notOHBasedDevices;
    int32_t ret = DeviceProfileManager::GetInstance().SyncWithNotOHBasedDevice(
        notOHBasedDevices, callerDescriptor, syncCompletedCallback);
    DeviceProfileManager::GetInstance().SyncWithNotOHBasedDeviceFailed(notOHBasedDevices, syncCompletedCallback);
    if (adapterAvailable) {
        EXPECT_EQ(ret, DP_SUCCESS);
    } else {
        EXPECT_NE(ret, DP_SUCCESS);
    }
}

/**
 * @tc.name: GetEntriesByKeysThree001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetEntriesByKeysThree001, TestSize.Level1)
{
    std::unique_ptr<DeviceProfileManager> manager_;
    manager_ = std::make_unique<DeviceProfileManager>();
    std::vector<std::string> keys;
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId("networkIdThree");
    std::vector<DistributedKv::Entry> ret = manager_->GetEntriesByKeys(keys);
    DeviceProfileManager::GetInstance().FixDataOnDeviceOnline(deviceInfo);
    DeviceProfileManager::GetInstance().NotifyNotOHBaseOnline(deviceInfo);
    DeviceProfileManager::GetInstance().E2ESyncDynamicProfile(deviceInfo);
    EXPECT_NE(ret.size(), 100);
}

/**
 * @tc.name: GetEntriesByKeysThree002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetEntriesByKeysThree002, TestSize.Level1)
{
    std::unique_ptr<DeviceProfileManager> manager_;
    manager_ = std::make_unique<DeviceProfileManager>();
    manager_->deviceProfileStore_ = nullptr;
    std::vector<std::string> keys = {"keyThree1"};
    TrustedDeviceInfo deviceInfo;
    std::vector<DistributedKv::Entry> ret = manager_->GetEntriesByKeys(keys);
    DeviceProfileManager::GetInstance().OnDeviceOnline(deviceInfo);
    DeviceProfileManager::GetInstance().FixDataOnDeviceOnline(deviceInfo);
    DeviceProfileManager::GetInstance().NotifyNotOHBaseOnline(deviceInfo);
    DeviceProfileManager::GetInstance().E2ESyncDynamicProfile(deviceInfo);
    EXPECT_NE(ret.size(), 100);
}

/**
 * @tc.name: GetEntriesByKeysThree003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetEntriesByKeysThree003, TestSize.Level1)
{
    std::unique_ptr<DeviceProfileManager> manager_;
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>("111Three",
        "222Three",
        std::make_shared<KvDataChangeListener>("333Three"),
        std::make_shared<KvSyncCompletedListener>("444Three"),
        std::make_shared<KvDeathRecipient>("555Three"),
        DistributedKv::TYPE_DYNAMICAL);
    manager_ = std::make_unique<DeviceProfileManager>();
    manager_->deviceProfileStore_ = kvStore;
    std::vector<std::string> keys = {"keyThree1"};
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId("networkIdThree");
    deviceInfo.SetOsType(OHOS_TYPE);
    std::vector<DistributedKv::Entry> ret = manager_->GetEntriesByKeys(keys);
    DeviceProfileManager::GetInstance().OnDeviceOnline(deviceInfo);
    DeviceProfileManager::GetInstance().FixDataOnDeviceOnline(deviceInfo);
    DeviceProfileManager::GetInstance().NotifyNotOHBaseOnline(deviceInfo);
    DeviceProfileManager::GetInstance().E2ESyncDynamicProfile(deviceInfo);
    EXPECT_NE(ret.size(), 100);
}

/**
 * @tc.name: GetProfilesByOwnerThree002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerThreeTest, GetProfilesByOwnerThree002, TestSize.Level1)
{
    std::string uuid = "uuidThree";
    std::map<std::string, std::string> values;
    std::unique_ptr<DeviceProfileManager> manager_;
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>("111Three2",
        "222Three2",
        std::make_shared<KvDataChangeListener>("333Three2"),
        std::make_shared<KvSyncCompletedListener>("444Three2"),
        std::make_shared<KvDeathRecipient>("555Three2"),
        DistributedKv::TYPE_DYNAMICAL);
    manager_ = std::make_unique<DeviceProfileManager>();
    manager_->deviceProfileStore_ = kvStore;
    int32_t ret = manager_->GetProfilesByOwner(uuid, values);
    EXPECT_NE(ret, DP_SUCCESS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
