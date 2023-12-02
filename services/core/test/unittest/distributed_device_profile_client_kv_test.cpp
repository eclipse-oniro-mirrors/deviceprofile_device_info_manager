/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "refbase.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_enums.h"
#include "device_profile.h"
#include "service_profile.h"
#include "dp_subscribe_info.h"
#include "i_sync_completed_callback.h"
#include "characteristic_profile.h"
#include "distributed_device_profile_client.h"

using namespace testing::ext;
using namespace OHOS::DistributedDeviceProfile;
using namespace std;

class DistributedDeviceProfileClientKvTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedDeviceProfileClientKvTest::SetUpTestCase(void) {
}

void DistributedDeviceProfileClientKvTest::TearDownTestCase(void) {
}

void DistributedDeviceProfileClientKvTest::SetUp() {
}

void DistributedDeviceProfileClientKvTest::TearDown() {
}

class SubscribeDPChangeListener : public ProfileChangeListenerStub {
public:
    SubscribeDPChangeListener()
    {
    }
    ~SubscribeDPChangeListener()
    {
    }
    int32_t OnTrustDeviceProfileAdd(const TrustDeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnTrustDeviceProfileDelete(const TrustDeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnTrustDeviceProfileUpdate(const TrustDeviceProfile &oldProfile, const TrustDeviceProfile &newProfile)
    {
        return 0;
    }
    int32_t OnDeviceProfileAdd(const DeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnDeviceProfileDelete(const DeviceProfile &profile)
    {
        return 0;
    }
    int32_t OnDeviceProfileUpdate(const DeviceProfile &oldProfile, const DeviceProfile &newProfile)
    {
        return 0;
    }
    int32_t OnServiceProfileAdd(const ServiceProfile &profile)
    {
        return 0;
    }
    int32_t OnServiceProfileDelete(const ServiceProfile &profile)
    {
        return 0;
    }
    int32_t OnServiceProfileUpdate(const ServiceProfile &oldProfile, const ServiceProfile &newProfile)
    {
        return 0;
    }
    int32_t OnCharacteristicProfileAdd(const CharacteristicProfile &profile)
    {
        return 0;
    }
    int32_t OnCharacteristicProfileDelete(const CharacteristicProfile &profile)
    {
        return 0;
    }
    int32_t OnCharacteristicProfileUpdate(const CharacteristicProfile &oldProfile,
                                          const CharacteristicProfile &newProfile)
    {
        return 0;
    }
};

/**
 * @tc.name:PutServiceProfile001
 * @tc.desc: PutServiceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceProfile001, TestSize.Level1)
{
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId("deviceId");
    serviceProfile.SetServiceName("serviceName");
    serviceProfile.SetServiceType("serviceType");

    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceProfile(serviceProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutServiceProfileBatch001
 * @tc.desc: PutServiceProfileBatch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceProfileBatch001, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    
    ServiceProfile serviceProfile1;
    serviceProfile1.SetDeviceId("deviceId1");
    serviceProfile1.SetServiceName("serviceName1");
    serviceProfile1.SetServiceType("serviceType1");
    ServiceProfile serviceProfile2;
    serviceProfile2.SetDeviceId("deviceId2");
    serviceProfile2.SetServiceName("serviceName2");
    serviceProfile2.SetServiceType("serviceType2");
    serviceProfiles.push_back(serviceProfile1);
    serviceProfiles.push_back(serviceProfile2);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutServiceProfileBatch002
 * @tc.desc: PutServiceProfileBatch failed, ServiceProfiles size is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutServiceProfileBatch002, TestSize.Level1)
{
    vector<ServiceProfile> serviceProfiles;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutServiceProfileBatch(serviceProfiles);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name:PutCharacteristicProfile001
 * @tc.desc: PutCharacteristicProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutCharacteristicProfile001, TestSize.Level1)
{
    CharacteristicProfile charProfile;
    charProfile.SetDeviceId("deviceId");
    charProfile.SetServiceName("serviceName");
    charProfile.SetCharacteristicKey("characteristicKey");
    charProfile.SetCharacteristicValue("characteristicValue");
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutCharacteristicProfile(charProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutCharacteristicProfileBatch001
 * @tc.desc: PutCharacteristicProfileBatch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutCharacteristicProfileBatch001, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    
    CharacteristicProfile charProfile1;
    charProfile1.SetDeviceId("deviceId1");
    charProfile1.SetServiceName("serviceName1");
    charProfile1.SetCharacteristicKey("characteristicKey1");
    charProfile1.SetCharacteristicValue("characteristicValue1");
    CharacteristicProfile charProfile2;
    charProfile2.SetDeviceId("deviceId2");
    charProfile2.SetServiceName("serviceName2");
    charProfile2.SetCharacteristicKey("characteristicKey2");
    charProfile2.SetCharacteristicValue("characteristicValue2");
    charProfiles.push_back(charProfile1);
    charProfiles.push_back(charProfile2);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name:PutCharacteristicProfileBatch002
 * @tc.desc: PutCharacteristicProfileBatch failed, CharacteristicProfiles size is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, PutCharacteristicProfileBatch002, TestSize.Level1)
{
    vector<CharacteristicProfile> charProfiles;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    EXPECT_EQ(errCode, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetDeviceProfile001
 * @tc.desc: GetDeviceProfile success, DeviceProfile Set and Get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetDeviceProfile001, TestSize.Level1)
{
    string deviceId = "deviceId";
    DeviceProfile deviceProfile;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(deviceId, deviceProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);

    DeviceProfile deviceProfile1;
    deviceProfile1.SetDeviceId("anything");
    deviceProfile1.SetDeviceTypeName("anything");
    deviceProfile1.SetDeviceTypeId(0);
    deviceProfile1.SetDeviceName("anything");
    deviceProfile1.SetManufactureName("anything");
    deviceProfile1.SetDeviceModel("anything");
    deviceProfile1.SetSerialNumberId("anything");
    deviceProfile1.SetStorageCapability(1);
    deviceProfile1.SetOsSysCap("anything");
    deviceProfile1.SetOsApiLevel(1);
    deviceProfile1.SetOsVersion("anything");
    deviceProfile1.SetOsType(1);

    deviceProfile1.GetDeviceId();
    deviceProfile1.GetDeviceTypeName();
    deviceProfile1.GetDeviceTypeId();
    deviceProfile1.GetDeviceName();
    deviceProfile1.GetManufactureName();
    deviceProfile1.GetDeviceModel();
    deviceProfile1.GetSerialNumberId();
    deviceProfile1.GetStorageCapability();
    deviceProfile1.GetOsSysCap();
    deviceProfile1.GetOsApiLevel();
    deviceProfile1.GetOsVersion();
    deviceProfile1.GetOsType();
}

/**
 * @tc.name: GetServiceProfile001
 * @tc.desc: GetServiceProfile success, ServiceProfile Get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetServiceProfile001, TestSize.Level1)
{
    string deviceId = "deviceId";
    string serviceName = "serviceName";
    ServiceProfile serviceProfile;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetServiceProfile(
        deviceId, serviceName, serviceProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: GetCharacteristicProfile001
 * @tc.desc: GetCharacteristicProfile success, CharacteristicProfile Get
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, GetCharacteristicProfile001, TestSize.Level1)
{
    string deviceId = "deviceId";
    string serviceName = "serviceName";
    string characteristicKey = "characteristicKey";
    CharacteristicProfile characteristicProfile;
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().GetCharacteristicProfile(
            deviceId, serviceName, characteristicKey, characteristicProfile);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);

    characteristicProfile.GetDeviceId();
    characteristicProfile.GetServiceName();
    characteristicProfile.GetCharacteristicKey();
}

/**
 * @tc.name: DeleteServiceProfile001
 * @tc.desc: DeleteServiceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteServiceProfile001, TestSize.Level1)
{
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().DeleteServiceProfile(
            "deviceId", "serviceName");
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: DeleteCharacteristicProfile001
 * @tc.desc: DeleteCharacteristicProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, DeleteCharacteristicProfile001, TestSize.Level1)
{
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().DeleteCharacteristicProfile(
            "deviceId", "serviceName", "characteristicKey");
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: SubscribeDeviceProfile001
 * @tc.desc: SubscribeDeviceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SubscribeDeviceProfile001, TestSize.Level1)
{
    string subscribeKey = "subscribeKey";
    int32_t saId = 4801;
    unordered_set<ProfileChangeType> subscribeTypes = {
        ProfileChangeType::SERVICE_PROFILE_ADD,
        ProfileChangeType::SERVICE_PROFILE_UPDATE,
        ProfileChangeType::SERVICE_PROFILE_DELETE
    };
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener = new(nothrow) SubscribeDPChangeListener;
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().SubscribeDeviceProfile(subscribeInfo);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: UnSubscribeDeviceProfile001
 * @tc.desc: UnSubscribeDeviceProfile success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, UnSubscribeDeviceProfile001, TestSize.Level1)
{
    string subscribeKey = "subscribeKey";
    int32_t saId = 4801;
    unordered_set<ProfileChangeType> subscribeTypes = {
            ProfileChangeType::SERVICE_PROFILE_ADD,
            ProfileChangeType::SERVICE_PROFILE_UPDATE,
            ProfileChangeType::SERVICE_PROFILE_DELETE
    };
    OHOS::sptr<IProfileChangeListener> subscribeDPChangeListener = new(nothrow) SubscribeDPChangeListener;
    SubscribeInfo subscribeInfo(saId, subscribeKey, subscribeTypes, subscribeDPChangeListener);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().UnSubscribeDeviceProfile(subscribeInfo);
    EXPECT_EQ(errCode, DP_PERMISSION_DENIED);
}

/**
 * @tc.name: SyncDeviceProfile001
 * @tc.desc: SyncDeviceProfile failed, SyncCb is nullptr!
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedDeviceProfileClientKvTest, SyncDeviceProfile001, TestSize.Level1)
{
    SyncOptions syncOptions;
    OHOS::sptr<ISyncCompletedCallback> syncCb = nullptr;
    
    syncOptions.AddDevice("deviceId1");
    syncOptions.AddDevice("deviceId2");
    syncOptions.SetSyncMode(SyncMode::MIN);
    
    int32_t errCode = DistributedDeviceProfileClient::GetInstance().SyncDeviceProfile(syncOptions, syncCb);
    EXPECT_EQ(errCode, DP_SYNC_DEVICE_FAIL);
}

