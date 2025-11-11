/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <mutex>
#include <memory>
#include <algorithm>
#include <dlfcn.h>
#include <vector>
#include <list>

#include "kv_adapter.h"
#include "profile_cache.h"
#include "profile_control_utils.h"
#include "content_sensor_manager_utils.h"
#include "device_manager.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_log.h"
#include "listener/kv_data_change_listener.h"
#include "listener/kv_sync_completed_listener.h"
#include "listener/kv_store_death_recipient.h"
#include "switch_adapter.h"
#include "trusted_device_info.h"


namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
using namespace std;

namespace {
    const std::string TAG = "ProfileControlUtilsTest";
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "dp_kv_store";
}

class ProfileControlUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class KVAdapterTest : public KVAdapter {
public:
    KVAdapterTest() : KVAdapter("", "", nullptr, nullptr, nullptr, DistributedKv::TYPE_DYNAMICAL) {}
    int32_t result = DP_SUCCESS;
    int32_t DeleteBatch(const std::vector<std::string> &keys) override
    {
        return result;
    }
};

void ProfileControlUtilsTest::SetUpTestCase() {
}

void ProfileControlUtilsTest::TearDownTestCase() {
}

void ProfileControlUtilsTest::SetUp() {
}

void ProfileControlUtilsTest::TearDown() {
}

/**
 * @tc.name: PutDeviceProfile001
 * @tc.desc: PutDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutDeviceProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    DeviceProfile deviceProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutDeviceProfile(kvStore, deviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile002
 * @tc.desc: PutDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutDeviceProfile002, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    DeviceProfile deviceProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutDeviceProfile(kvStore, deviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile003
 * @tc.desc: PutDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutDeviceProfile003, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    DeviceProfile deviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceId";
    deviceProfile.SetDeviceId("deviceId");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutDeviceProfile(kvStore, deviceProfile);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
 * @tc.name: PutDeviceProfile004
 * @tc.desc: PutDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutDeviceProfile004, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    DeviceProfile deviceProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "anything1";
    deviceProfile1.SetDeviceId("anything1");
    deviceProfile1.SetDeviceName("anything");
    deviceProfile1.SetManufactureName("anything");
    deviceProfile1.SetDeviceModel("anything");
    deviceProfile1.SetStorageCapability(1);
    deviceProfile1.SetOsSysCap("anything");
    deviceProfile1.SetOsApiLevel(1);
    deviceProfile1.SetOsVersion("anything");
    deviceProfile1.SetOsType(1);
    ProfileCache::GetInstance().AddDeviceProfile(deviceProfile1);
    ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile1);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutDeviceProfile(kvStore, deviceProfile1);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutServiceProfile001
 * @tc.desc: PutServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutServiceProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    ServiceProfile serviceProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutServiceProfile(kvStore, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutServiceProfile002
 * @tc.desc: PutServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutServiceProfile002, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("deviceId");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutServiceProfile(kvStore, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutServiceProfile003
 * @tc.desc: PutServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutServiceProfile003, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    ServiceProfile serviceProfile;
    serviceProfile.SetServiceName("ServiceName");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutServiceProfile(kvStore, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutServiceProfile004
 * @tc.desc: PutServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutServiceProfile004, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    ServiceProfile serviceProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceId";
    serviceProfile.SetDeviceId("deviceId");
    serviceProfile.SetServiceName("ServiceName");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutServiceProfile(kvStore, serviceProfile);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
 * @tc.name: PutServiceProfile005
 * @tc.desc: PutServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutServiceProfile005, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    ServiceProfile serviceProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceId1";
    serviceProfile1.SetDeviceId("deviceId1");
    serviceProfile1.SetServiceName("serviceName1");
    serviceProfile1.SetServiceType("serviceType1");
    ProfileCache::GetInstance().AddServiceProfile(serviceProfile1);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutServiceProfile(kvStore, serviceProfile1);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutServiceProfileBatch001
 * @tc.desc: PutServiceProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutServiceProfileBatch001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    ServiceProfile serviceProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutServiceProfile(kvStore, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile001
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile002
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile002, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile003
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile003, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    charProfile.SetServiceName("ServiceName");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile004
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile004, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile005
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile005, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("ServiceName");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile006
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile006, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("ServiceName");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
 * @tc.name: PutCharacteristicProfile007
 * @tc.desc: PutCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfile007, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("ServiceName");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfile(kvStore, charProfile);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile001
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile001, TestSize.Level1)
{
    std::string appId;
    CharacteristicProfile charProfile;
    charProfile.SetServiceName("ServiceName");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile002
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile002, TestSize.Level1)
{
    std::string appId;
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile003
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile003, TestSize.Level1)
{
    std::string appId;
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("ServiceName");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile004
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile004, TestSize.Level1)
{
    std::string appId;
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("ServiceName");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile005
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile005, TestSize.Level1)
{
    std::string appId;
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("ServiceName");
    charProfile.SetCharacteristicKey("CharacteristicKey");
    ProfileCache::GetInstance().AddCharProfile(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile006
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile006, TestSize.Level1)
{
    std::string appId;
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfile.SetCharacteristicKey(SWITCH_STATUS);
    charProfile.SetCharacteristicValue("1");

    ProfileCache::GetInstance().AddCharProfile(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutSwitchCharacteristicProfile007
 * @tc.desc: PutSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfile007, TestSize.Level1)
{
    std::string appId = "appId";
    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfile.SetCharacteristicKey(SWITCH_STATUS);
    charProfile.SetCharacteristicValue("1");

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfile(appId, charProfile);
    EXPECT_EQ(ret, DP_CACHE_EXIST);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch001
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch001, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch002
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch002, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    charProfile.SetCharacteristicKey(SWITCH_STATUS);
    charProfile.SetCharacteristicValue("1");
    charProfiles.push_back(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch003
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch003, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetCharacteristicValue("1");
    charProfiles.push_back(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch004
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch004, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfiles.push_back(charProfile);
    charProfiles.push_back(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch005
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch005, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfile.SetCharacteristicKey(SWITCH_STATUS);
    charProfile.SetCharacteristicValue("1");

    charProfiles.push_back(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch006
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch006, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfile.SetCharacteristicKey("key");
    charProfile.SetCharacteristicValue("1");

    ProfileCache::GetInstance().AddCharProfile(charProfile);

    charProfiles.push_back(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch007
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch007, TestSize.Level1)
{
    std::string appId = "appId";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "DeviceId";
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfile.SetCharacteristicKey(SWITCH_STATUS);
    charProfile.SetCharacteristicValue("1");

    ProfileCache::GetInstance().AddCharProfile(charProfile);
    charProfiles.push_back(charProfile);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
 * @tc.name: PutSwitchCharacteristicProfileBatch008
 * @tc.desc: PutSwitchCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutSwitchCharacteristicProfileBatch008, TestSize.Level1)
{
    std::string appId = "";
    std::vector<CharacteristicProfile> charProfiles;

    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("DeviceId");
    charProfile.SetServiceName("deviceStatus");
    charProfile.SetCharacteristicKey(SWITCH_STATUS);
    charProfile.SetCharacteristicValue("1");

    ProfileCache::GetInstance().AddCharProfile(charProfile);

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutSwitchCharacteristicProfileBatch(appId, charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfileBatch001
 * @tc.desc: PutCharacteristicProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, PutCharacteristicProfileBatch001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::vector<CharacteristicProfile> charProfiles;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->PutCharacteristicProfileBatch(kvStore, charProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetDeviceProfile001
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetDeviceProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    DeviceProfile deviceProfile;
    std::string deviceId;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetDeviceProfile(kvStore, deviceId, deviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetDeviceProfile002
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetDeviceProfile002, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    DeviceProfile deviceProfile;
    std::string deviceId;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetDeviceProfile(kvStore, deviceId, deviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetDeviceProfile003
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetDeviceProfile003, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    DeviceProfile deviceProfile;
    std::string deviceId = "deviceId";

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetDeviceProfile(kvStore, deviceId, deviceProfile);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: GetDeviceProfile004
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetDeviceProfile004, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    DeviceProfile deviceProfile;
    std::string deviceId = "deviceId";

    ContentSensorManagerUtils::GetInstance().localUdid_ = deviceId;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetDeviceProfile(kvStore, deviceId, deviceProfile);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
    ContentSensorManagerUtils::GetInstance().localUdid_ = "";
}

/**
 * @tc.name: GetServiceProfile001
 * @tc.desc: GetServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetServiceProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    std::string deviceId = "deviceId";
    std::string serviceName;
    ServiceProfile serviceProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetServiceProfile(kvStore, deviceId, serviceName, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetServiceProfile002
 * @tc.desc: GetServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetServiceProfile002, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string deviceId = "deviceId";
    std::string serviceName;
    ServiceProfile serviceProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetServiceProfile(kvStore, deviceId, serviceName, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetServiceProfile003
 * @tc.desc: GetServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetServiceProfile003, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string deviceId;
    std::string serviceName = "serviceName";
    ServiceProfile serviceProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetServiceProfile(kvStore, deviceId, serviceName, serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetServiceProfile004
 * @tc.desc: GetServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetServiceProfile004, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    ServiceProfile serviceProfile;

    ContentSensorManagerUtils::GetInstance().localUdid_ = "";
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetServiceProfile(kvStore, deviceId, serviceName, serviceProfile);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: GetServiceProfile005
 * @tc.desc: GetServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetServiceProfile005, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);

    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    ServiceProfile serviceProfile;

    ProfileCache::GetInstance().onlineDevMap_[deviceId] = deviceInfo;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetServiceProfile(kvStore, deviceId, serviceName, serviceProfile);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: GetServiceProfile006
 * @tc.desc: GetServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetServiceProfile006, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    ServiceProfile serviceProfile;

    ProfileCache::GetInstance().onlineDevMap_[deviceId] = deviceInfo;
    std::string serviceProfileKey = SVR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName;
    ProfileCache::GetInstance().serviceProfileMap_[serviceProfileKey] = serviceProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetServiceProfile(kvStore, deviceId, serviceName, serviceProfile);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetCharacteristicProfile001
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey;
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetCharacteristicProfile002
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile002, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string deviceId;
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetCharacteristicProfile003
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile003, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey;
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetCharacteristicProfile004
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile004, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey;
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetCharacteristicProfile005
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile005, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    ContentSensorManagerUtils::GetInstance().localUdid_ = "";
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: GetCharacteristicProfile006
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile006, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    ProfileCache::GetInstance().onlineDevMap_[deviceId] = deviceInfo;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: GetCharacteristicProfile007
 * @tc.desc: GetCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetCharacteristicProfile007, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = std::make_shared<KVAdapter>(APP_ID, STORE_ID,
        std::make_shared<KvDataChangeListener>(STORE_ID),
        std::make_shared<KvSyncCompletedListener>(STORE_ID), std::make_shared<KvDeathRecipient>(STORE_ID),
        DistributedKv::TYPE_DYNAMICAL);
    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    ProfileCache::GetInstance().onlineDevMap_[deviceId] = deviceInfo;
    std::string charProfileKey =
        CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + characteristicKey;
    ProfileCache::GetInstance().charProfileMap_[charProfileKey] = charProfile;
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetCharacteristicProfile(kvStore, deviceId, serviceName,
        characteristicKey, charProfile);
    ProfileCache::GetInstance().charProfileMap_.erase(charProfileKey);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: RefreshLocalSwitchProfile001
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, RefreshLocalSwitchProfile001, TestSize.Level1)
{
    std::string appId = "appId";
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->RefreshLocalSwitchProfile(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: RefreshLocalSwitchProfile002
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, RefreshLocalSwitchProfile002, TestSize.Level1)
{
    std::string appId = "";
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    ProfileCache::GetInstance().localNetworkId_ = "localNetwork";
    int32_t ret = profileControlUtils->RefreshLocalSwitchProfile(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: RefreshLocalSwitchProfile003
 * @tc.desc: RefreshLocalSwitchProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, RefreshLocalSwitchProfile003, TestSize.Level1)
{
    std::string appId = "appId";
  
    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    ProfileCache::GetInstance().localNetworkId_ = "localNetwork";
    int32_t ret = profileControlUtils->RefreshLocalSwitchProfile(appId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile001
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile001, TestSize.Level1)
{
    std::string appId = "appId";
    std::string deviceId = "";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile002
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile002, TestSize.Level1)
{
    std::string appId = "appId";
    std::string deviceId = "deviceId";
    std::string serviceName = "";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile003
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile003, TestSize.Level1)
{
    std::string appId = "appId";
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "";
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile004
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile004, TestSize.Level1)
{
    std::string appId = "";
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile005
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile005, TestSize.Level1)
{
    std::string appId = "appId";
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile006
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile006, TestSize.Level1)
{
    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string appId = "appId";
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    CharacteristicProfile charProfile;

    ProfileCache::GetInstance().onlineDevMap_[deviceId] = deviceInfo;
    std::string charProfileKey =
        CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + characteristicKey;
    ProfileCache::GetInstance().charProfileMap_[charProfileKey] = charProfile;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
    ProfileCache::GetInstance().charProfileMap_.erase(charProfileKey);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
}

/**
 * @tc.name: GetSwitchCharacteristicProfile007
 * @tc.desc: GetSwitchCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileControlUtilsTest, GetSwitchCharacteristicProfile007, TestSize.Level1)
{
    std::string peerNetworkId = "peerNetworkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    std::string appId = "appId";
    std::string deviceId = "deviceId";
    deviceInfo.SetUdid(deviceId);
    std::string serviceName = "serviceName";
    std::string characteristicKey = "SwitchStatus";
    CharacteristicProfile charProfile;

    ProfileCache::GetInstance().onlineDevMap_[deviceId] = deviceInfo;

    auto profileControlUtils = std::shared_ptr<ProfileControlUtils>();
    int32_t ret = profileControlUtils->GetSwitchCharacteristicProfile(appId, deviceId,
        serviceName, characteristicKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceId);
}

/**
 * @tc.name: DeleteServiceInfoProfile001
 * @tc.desc: kvStore 为 nullptr，返回 DP_INVALID_PARAMS
 * @tc.type: FUNC
 */
HWTEST_F(ProfileControlUtilsTest, DeleteServiceInfoProfile001, TestSize.Level1)
{
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    int32_t regServiceId = 123;
    int32_t userId = 0;
    int32_t ret = ProfileControlUtils::DeleteServiceInfoProfile(kvStore, regServiceId, userId);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

/**
 * @tc.name: DeleteServiceInfoProfile002
 * @tc.desc: DeleteBatch 失败，返回 DP_DEL_KV_DB_FAIL
 * @tc.type: FUNC
 */

HWTEST_F(ProfileControlUtilsTest, DeleteServiceInfoProfile002, TestSize.Level1)
{
    auto kvStore = std::make_shared<KVAdapterTest>();
    kvStore->result = DP_DEL_KV_DB_FAIL;
    int32_t regServiceId = 123;
    int32_t userId = 0;
    int32_t ret = ProfileControlUtils::DeleteServiceInfoProfile(kvStore, regServiceId, userId);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}

/**
 * @tc.name: DeleteServiceInfoProfile003
 * @tc.desc: 正常删除，返回 DP_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ProfileControlUtilsTest, DeleteServiceInfoProfile003, TestSize.Level1)
{
    auto kvStore = std::make_shared<KVAdapterTest>();
    kvStore->result = DP_SUCCESS;
    int32_t regServiceId = 123;
    int32_t userId = 0;
    int32_t ret = ProfileControlUtils::DeleteServiceInfoProfile(kvStore, regServiceId, userId);
    EXPECT_NE(ret, DP_READ_PARCEL_FAIL);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
