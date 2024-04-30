/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#define private   public
#define protected public
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
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing::ext;
using namespace std;

class DeviceProfileManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DeviceProfileManagerTest::SetUpTestCase(void) {
}

void DeviceProfileManagerTest::TearDownTestCase(void) {
}

void DeviceProfileManagerTest::SetUp()
{
    DeviceProfileManager::GetInstance().Init();
}

void DeviceProfileManagerTest::TearDown() {
}

class SyncCallback : public SyncCompletedCallbackStub {
public:
    void OnSyncCompleted(const map<string, SyncStatus>& syncResults) {
    }
};

/**
 * @tc.name: Init001
 * @tc.desc: Init succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, Init001, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().Init();
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: UnInit001
 * @tc.desc: UnInit succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, UnInit001, TestSize.Level1)
{
    int32_t ret = DeviceProfileManager::GetInstance().UnInit();
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: ReInit001
 * @tc.desc: ReInit succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, ReInit001, TestSize.Level1)
{
    int32_t ret = DeviceProfileManager::GetInstance().ReInit();
    EXPECT_EQ(ret, DP_SUCCESS);
}


/**
 * @tc.name: PutDeviceProfile002
 * @tc.desc: PutDeviceProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutDeviceProfile002, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("");
    deviceProfile.SetDeviceTypeName("anything");
    deviceProfile.SetDeviceTypeId(0);
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutDeviceProfile004
 * @tc.desc: PutDeviceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutDeviceProfile004, TestSize.Level1)
{
    DeviceProfile deviceProfile10;
    deviceProfile10.SetDeviceId("anything10");
    deviceProfile10.SetDeviceTypeName("anything");
    deviceProfile10.SetDeviceTypeId(0);
    deviceProfile10.SetDeviceName("anything");
    deviceProfile10.SetManufactureName("anything");
    deviceProfile10.SetDeviceModel("anything");
    deviceProfile10.SetStorageCapability(1);
    deviceProfile10.SetOsSysCap("anything");
    deviceProfile10.SetOsApiLevel(1);
    deviceProfile10.SetOsVersion("anything");
    deviceProfile10.SetOsType(1);
    
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile10);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: PutDeviceProfile005
 * @tc.desc: PutDeviceProfile failed, PutDeviceProfile fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutDeviceProfile005, TestSize.Level1)
{
    DeviceProfile deviceProfile11;
    deviceProfile11.SetDeviceId("anything11");
    deviceProfile11.SetDeviceTypeName("anything");
    deviceProfile11.SetDeviceTypeId(0);
    deviceProfile11.SetDeviceName("anything");
    deviceProfile11.SetManufactureName("anything");
    deviceProfile11.SetDeviceModel("anything");
    deviceProfile11.SetStorageCapability(1);
    deviceProfile11.SetOsSysCap("anything");
    deviceProfile11.SetOsApiLevel(1);
    deviceProfile11.SetOsVersion("anything");
    deviceProfile11.SetOsType(1);

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().PutDeviceProfile(deviceProfile11);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}


/**
 * @tc.name: PutServiceProfile002
 * @tc.desc: PutServiceProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutServiceProfile002, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("");
    serviceProfile.SetServiceName("serviceName");
    serviceProfile.SetServiceType("serviceType");
    
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutServiceProfile004
 * @tc.desc: PutServiceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutServiceProfile004, TestSize.Level1)
{
    ServiceProfile serviceProfile10;
    serviceProfile10.SetDeviceId("deviceId10");
    serviceProfile10.SetServiceName("serviceName10");
    serviceProfile10.SetServiceType("serviceType10");
    
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile10);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: PutServiceProfile005
 * @tc.desc: PutServiceProfile failed, PutServiceProfile fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutServiceProfile005, TestSize.Level1)
{
    ServiceProfile serviceProfile11;
    serviceProfile11.SetDeviceId("deviceId11");
    serviceProfile11.SetServiceName("serviceName11");
    serviceProfile11.SetServiceType("serviceType11");

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile11);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: PutCharacteristicProfile002
 * @tc.desc: PutCharacteristicProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutCharacteristicProfile002, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("");
    charProfile.SetServiceName("serviceName");
    charProfile.SetCharacteristicKey("characteristicKey");
    charProfile.SetCharacteristicValue("characteristicValue");
    
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: PutCharacteristicProfile004
 * @tc.desc: PutCharacteristicProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutCharacteristicProfile004, TestSize.Level1)
{
    CharacteristicProfile charProfile10;
    charProfile10.SetDeviceId("deviceId10");
    charProfile10.SetServiceName("serviceName10");
    charProfile10.SetCharacteristicKey("characteristicKey10");
    charProfile10.SetCharacteristicValue("characteristicValue10");
    
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile10);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: PutCharacteristicProfile005
 * @tc.desc: PutCharacteristicProfile failed, PutCharacteristicProfile fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, PutCharacteristicProfile005, TestSize.Level1)
{
    CharacteristicProfile charProfile11;
    charProfile11.SetDeviceId("deviceId11");
    charProfile11.SetServiceName("serviceName11");
    charProfile11.SetCharacteristicKey("characteristicKey11");
    charProfile11.SetCharacteristicValue("characteristicValue11");

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfile(charProfile11);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetDeviceProfile002
 * @tc.desc: GetDeviceProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetDeviceProfile002, TestSize.Level1)
{
    string deviceId = "";
    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetDeviceProfile003
 * @tc.desc: GetDeviceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetDeviceProfile003, TestSize.Level1)
{
    string deviceId = "anything12";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetDeviceProfile004
 * @tc.desc: GetDeviceProfile failed, Get data fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetDeviceProfile004, TestSize.Level1)
{
    string deviceId = "#anything13";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfile outDeviceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceId, outDeviceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetServiceProfile002
 * @tc.desc: GetServiceProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetServiceProfile002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceName";
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    
    deviceId = "deviceId";
    serviceName = "";
    ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetServiceProfile003
 * @tc.desc: GetServiceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetServiceProfile003, TestSize.Level1)
{
    string deviceId = "deviceId12";
    string serviceName = "serviceName12";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetServiceProfile004
 * @tc.desc: GetServiceProfile failed, Get data fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetServiceProfile004, TestSize.Level1)
{
    string deviceId = "#deviceId13";
    string serviceName = "serviceName13";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    ServiceProfile outServiceProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetServiceProfile(deviceId, serviceName, outServiceProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetCharacteristicProfile002
 * @tc.desc: GetCharacteristicProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetCharacteristicProfile002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceName";
    string characteristicKey = "characteristicKey";
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    
    deviceId = "deviceId";
    serviceName = "serviceName";
    characteristicKey = "";
    ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetCharacteristicProfile003
 * @tc.desc: GetCharacteristicProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetCharacteristicProfile003, TestSize.Level1)
{
    string deviceId = "deviceId12";
    string serviceName = "serviceName12";
    string characteristicKey = "characteristicKey12";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetCharacteristicProfile004
 * @tc.desc: GetCharacteristicProfile failed, Get data fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetCharacteristicProfile004, TestSize.Level1)
{
    string deviceId = "deviceId13";
    string serviceName = "serviceName13";
    string characteristicKey = "characteristicKey13";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    CharacteristicProfile outCharProfile;
    int32_t ret = DeviceProfileManager::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, outCharProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}


/**
 * @tc.name: DeleteServiceProfile002
 * @tc.desc: DeleteServiceProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeleteServiceProfile002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceName";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    
    deviceId = "deviceId";
    serviceName = "";
    ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteServiceProfile003
 * @tc.desc: DeleteServiceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeleteServiceProfile003, TestSize.Level1)
{
    string deviceId = "deviceId14";
    string serviceName = "serviceName14";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: DeleteServiceProfile004
 * @tc.desc: DeleteServiceProfile failed, DeleteServiceProfile fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeleteServiceProfile004, TestSize.Level1)
{
    string deviceId = "deviceId15";
    string serviceName = "serviceName15";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    EXPECT_EQ(ret, DP_DEL_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}


/**
 * @tc.name: DeleteCharacteristicProfile002
 * @tc.desc: DeleteCharacteristicProfile failed, the profile is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeleteCharacteristicProfile002, TestSize.Level1)
{
    string deviceId = "";
    string serviceName = "serviceName";
    string characteristicKey = "characteristicKey";
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    
    deviceId = "deviceId";
    serviceName = "serviceName";
    characteristicKey = "";
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteCharacteristicProfile003
 * @tc.desc: DeleteCharacteristicProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeleteCharacteristicProfile003, TestSize.Level1)
{
    string deviceId = "deviceId14";
    string serviceName = "serviceName14";
    string characteristicKey = "characteristicKey14";
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: DeleteCharacteristicProfile004
 * @tc.desc: DeleteCharacteristicProfile failed, DeleteServiceProfile fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeleteCharacteristicProfile004, TestSize.Level1)
{
    string deviceId = "deviceId15";
    string serviceName = "serviceName15";
    string characteristicKey = "characteristicKey15";
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    int32_t ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    EXPECT_EQ(ret, DP_DEL_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetAllDeviceProfile001
 * @tc.desc: GetAllDeviceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllDeviceProfile001, TestSize.Level1)
{
    vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetAllDeviceProfile002
 * @tc.desc: GetAllDeviceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllDeviceProfile002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetAllDeviceProfile003
 * @tc.desc: GetAllDeviceProfile failed, Get data fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllDeviceProfile003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetAllServiceProfile001
 * @tc.desc: GetAllServiceProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllServiceProfile001, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetAllServiceProfile002
 * @tc.desc: GetAllServiceProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllServiceProfile002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetAllServiceProfile003
 * @tc.desc: GetAllServiceProfile failed, Get data fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllServiceProfile003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetAllCharacteristicProfile001
 * @tc.desc: GetAllCharacteristicProfile succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllCharacteristicProfile001, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetAllCharacteristicProfile002
 * @tc.desc: GetAllCharacteristicProfile failed, deviceProfileStore is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllCharacteristicProfile002, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: GetAllCharacteristicProfile003
 * @tc.desc: GetAllCharacteristicProfile failed, Get data fail.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, GetAllCharacteristicProfile003, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
}

/**
 * @tc.name: SyncDeviceProfile001
 * @tc.desc: SyncDeviceProfile failed, Params is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, SyncDeviceProfile001, TestSize.Level1)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    OHOS::sptr<OHOS::IRemoteObject> syncCb = nullptr;
    
    syncOptions.AddDevice("deviceId1");
    syncOptions.AddDevice("deviceId2");
    syncOptions.SetSyncMode(SyncMode::MIN);
    
    int32_t errCode = DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name: SyncDeviceProfile002
 * @tc.desc: SyncDeviceProfile failed, Params is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, SyncDeviceProfile002, TestSize.Level1)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    OHOS::sptr<OHOS::IRemoteObject> syncCb = new(nothrow) SyncCallback();
    
    syncOptions.AddDevice("deviceId1");
    syncOptions.AddDevice("deviceId2");
    syncOptions.SetSyncMode(SyncMode::MAX);
    
    int32_t errCode = DeviceProfileManager::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeviceProfileMarshalling001
 * @tc.desc: DeviceProfile Marshalling and UnMarshalling succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeviceProfileMarshalling001, TestSize.Level1)
{
    OHOS::MessageParcel data;
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("anything");
    deviceProfile.SetDeviceTypeName("anything");
    deviceProfile.SetDeviceTypeId(0);
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    
    bool res1 = deviceProfile.Marshalling(data);
    EXPECT_EQ(true, res1);
    
    bool res2 = deviceProfile.UnMarshalling(data);
    EXPECT_EQ(true, res2);
}

/**
 * @tc.name: DeviceProfileOperator001
 * @tc.desc: DeviceProfileOperator true.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeviceProfileOperator001, TestSize.Level1)
{
    DeviceProfile deviceProfile1;
    deviceProfile1.SetDeviceId("anything1");
    deviceProfile1.SetDeviceTypeName("anything1");
    deviceProfile1.SetDeviceTypeId(0);
    deviceProfile1.SetDeviceName("anything1");
    deviceProfile1.SetManufactureName("anything1");
    deviceProfile1.SetDeviceModel("anything1");
    deviceProfile1.SetStorageCapability(1);
    deviceProfile1.SetOsSysCap("anything1");
    deviceProfile1.SetOsApiLevel(1);
    deviceProfile1.SetOsVersion("anything1");
    deviceProfile1.SetOsType(1);
    
    DeviceProfile deviceProfile2;
    deviceProfile2.SetDeviceId("anything2");
    deviceProfile2.SetDeviceTypeName("anything2");
    deviceProfile2.SetDeviceTypeId(0);
    deviceProfile2.SetDeviceName("anything2");
    deviceProfile2.SetManufactureName("anything2");
    deviceProfile2.SetDeviceModel("anything2");
    deviceProfile2.SetStorageCapability(1);
    deviceProfile2.SetOsSysCap("anything2");
    deviceProfile2.SetOsApiLevel(1);
    deviceProfile2.SetOsVersion("anything2");
    deviceProfile2.SetOsType(1);
    
    bool res = deviceProfile1 != deviceProfile2;
    EXPECT_EQ(true, res);
}

/**
 * @tc.name: DeviceProfileDump001
 * @tc.desc: DeviceProfileDump succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeviceProfileDump001, TestSize.Level1)
{
    DeviceProfile deviceProfile;
    deviceProfile.SetDeviceId("anything");
    deviceProfile.SetDeviceTypeName("anything");
    deviceProfile.SetDeviceTypeId(0);
    deviceProfile.SetDeviceName("anything");
    deviceProfile.SetManufactureName("anything");
    deviceProfile.SetDeviceModel("anything");
    deviceProfile.SetStorageCapability(1);
    deviceProfile.SetOsSysCap("anything");
    deviceProfile.SetOsApiLevel(1);
    deviceProfile.SetOsVersion("anything");
    deviceProfile.SetOsType(1);
    
    string strJson = deviceProfile.dump();
    char fistChar = strJson.front();
    char lastChar = strJson.back();
    EXPECT_EQ('{', fistChar);
    EXPECT_EQ('}', lastChar);
}

/**
 * @tc.name: ServiceProfileConstructor001
 * @tc.desc: ServiceProfileConstructor succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, ServiceProfileConstructor001, TestSize.Level1)
{
    ServiceProfile serviceProfile = ServiceProfile("deviceId", "serviceName", "serviceType");
    EXPECT_EQ("deviceId", serviceProfile.GetDeviceId());
}

/**
 * @tc.name: LoadDpSyncAdapter001
 * @tc.desc: LoadDpSyncAdapter first branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, LoadDpSyncAdapter001, TestSize.Level1)
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
    EXPECT_EQ(true, ret);
}


/**
 * @tc.name: RunloadedFunction001
 * @tc.desc: RunloadedFunction001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, RunloadedFunction001, TestSize.Level1)
{
    OHOS::sptr<OHOS::IRemoteObject> syncCb = new(nothrow) SyncCallback();
    string deviceId = "DeviceId";
    int32_t ret = DeviceProfileManager::GetInstance().RunloadedFunction(deviceId, syncCb);
    EXPECT_EQ(ret, DP_LOAD_SYNC_ADAPTER_FAILED);

    DeviceProfileManager::GetInstance().isAdapterSoLoaded_ = true;
    ret = DeviceProfileManager::GetInstance().RunloadedFunction(deviceId, syncCb);
    EXPECT_EQ(ret, DP_LOAD_SYNC_ADAPTER_FAILED);
}
/**
 * @tc.name: RunloadedFunction002
 * @tc.desc: RunloadedFunction002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, RunloadedFunction002, TestSize.Level1)
{
    OHOS::sptr<OHOS::IRemoteObject> syncCb = new(nothrow) SyncCallback();
    string deviceId = ProfileUtils::GetLocalUdidFromDM();
    int32_t ret = DeviceProfileManager::GetInstance().RunloadedFunction(deviceId, syncCb);
    EXPECT_EQ(ret, DP_LOAD_SYNC_ADAPTER_FAILED);

    DeviceProfileManager::GetInstance().isAdapterSoLoaded_ = true;
    ret = DeviceProfileManager::GetInstance().RunloadedFunction(deviceId, syncCb);
    EXPECT_EQ(ret, DP_LOAD_SYNC_ADAPTER_FAILED);
}

/**
 * @tc.name: DeviceOnlineAutoSync001
 * @tc.desc: DeviceOnlineAutoSync001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, DeviceOnlineAutoSync001, TestSize.Level1)
{
    std::string peerNetworkId = "";
    int32_t ret = DeviceProfileManager::GetInstance().DeviceOnlineAutoSync(peerNetworkId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);

    peerNetworkId = ProfileUtils::GetLocalUdidFromDM();
    ret = DeviceProfileManager::GetInstance().DeviceOnlineAutoSync(peerNetworkId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: OnNodeOnline001
 * @tc.desc: OnNodeOnline001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, OnNodeOnline001, TestSize.Level1)
{
    std::string peerNetworkId = "";
    DeviceProfileManager::GetInstance().OnNodeOnline(peerNetworkId);

    peerNetworkId = ProfileUtils::GetLocalUdidFromDM();
    DeviceProfileManager::GetInstance().OnNodeOnline(peerNetworkId);
}

/**
 * @tc.name: OnNodeOffline001
 * @tc.desc: OnNodeOffline001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, OnNodeOffline001, TestSize.Level1)
{
    std::string peerNetworkId = "";
    DeviceProfileManager::GetInstance().OnNodeOffline(peerNetworkId);

    peerNetworkId = ProfileUtils::GetLocalUdidFromDM();
    DeviceProfileManager::GetInstance().OnNodeOffline(peerNetworkId);
}

/**
 * @tc.name: IsLocalOrOnlineDevice001
 * @tc.desc: IsLocalOrOnlineDevice001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, IsLocalOrOnlineDevice001, TestSize.Level1)
{
    std::string deviceId = "";
    bool ret = DeviceProfileManager::GetInstance().IsLocalOrOnlineDevice(deviceId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: IsLocalOrOnlineDevice002
 * @tc.desc: IsLocalOrOnlineDevice002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, IsLocalOrOnlineDevice002, TestSize.Level1)
{
    std::string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    bool ret = DeviceProfileManager::GetInstance().IsLocalOrOnlineDevice(deviceId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: IsLocalOrOnlineDevice003
 * @tc.desc: IsLocalOrOnlineDevice003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTest, IsLocalOrOnlineDevice0013, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    DeviceProfileManager::GetInstance().onlineDevUdidSet_.insert("deviceId");
    bool ret = DeviceProfileManager::GetInstance().IsLocalOrOnlineDevice(deviceId);
    EXPECT_EQ(ret, true);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
