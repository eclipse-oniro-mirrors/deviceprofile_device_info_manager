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
#include "content_sensor_manager_utils.h"
#include "gtest/gtest.h"
#include "profile_cache.h"
#include "profile_utils.h"
#include "i_sync_completed_callback.h"
#include "sync_completed_callback_stub.h"
#include "trusted_device_info.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;
using namespace std;

class ProfileCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileCacheTest::SetUpTestCase() {
}

void ProfileCacheTest::TearDownTestCase() {
}

void ProfileCacheTest::SetUp() {
}

void ProfileCacheTest::TearDown() {
}

class SyncCallback : public SyncCompletedCallbackStub {
public:
    void OnSyncCompleted(const map<string, SyncStatus>& syncResults) {
    }
};

HWTEST_F(ProfileCacheTest, AddDeviceProfile_001, TestSize.Level2)
{
    DeviceProfile deviceProfile;
    int32_t ret = ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    deviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    for (int i = 1; i < MAX_DEVICE_SIZE + 1; ++i) {
        ProfileCache::GetInstance().deviceProfileMap_[std::to_string(i)] = deviceProfile;
    }
    ret = ProfileCache::GetInstance().AddDeviceProfile(deviceProfile);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, AddServiceProfile_001, TestSize.Level2)
{
    ServiceProfile serviceProfile;
    int32_t ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string serName = "dp_serName";
    serviceProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);

    devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    for (int i = 1; i < MAX_DEVICE_SIZE + 1; ++i) {
        ProfileCache::GetInstance().serviceProfileMap_[std::to_string(i)] = serviceProfile;
    }
    ret = ProfileCache::GetInstance().AddServiceProfile(serviceProfile);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, AddCharProfile_001, TestSize.Level2)
{
    CharacteristicProfile charProfile;
    int32_t ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string serName = "dp_serName";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    std::string charKey = "dp_charKey";
    charProfile.SetCharacteristicKey(charKey);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);

    serName = "dp_serName";
    charProfile.SetServiceName(serName);
    charKey = "dp_charKey";
    charProfile.SetCharacteristicKey(charKey);
    for (int i = 1; i < MAX_DEVICE_SIZE + 1; ++i) {
        ProfileCache::GetInstance().charProfileMap_[std::to_string(i)] = charProfile;
    }
    ret = ProfileCache::GetInstance().AddCharProfile(charProfile);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, GetDeviceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    DeviceProfile deviceProfile;
    int32_t ret = ProfileCache::GetInstance().GetDeviceProfile(devId, deviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetDeviceProfile(devId, deviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    ProfileCache::GetInstance().deviceProfileMap_.clear();
    ret = ProfileCache::GetInstance().GetDeviceProfile(devId, deviceProfile);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, GetServiceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    ServiceProfile serviceProfile;
    int32_t ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);

    devId = "dp_devId";
    ProfileCache::GetInstance().serviceProfileMap_.clear();
    ret = ProfileCache::GetInstance().GetServiceProfile(devId, serName, serviceProfile);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, GetCharacteristicProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    charKey = "dp_charKey";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);

    serName = "dp_serName";
    ProfileCache::GetInstance().charProfileMap_.clear();
    ret = ProfileCache::GetInstance().GetCharacteristicProfile(devId, serName, charKey, charProfile);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret);
}

HWTEST_F(ProfileCacheTest, DeleteDeviceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    int32_t ret = ProfileCache::GetInstance().DeleteDeviceProfile(devId);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteDeviceProfile(devId);
    EXPECT_EQ(DP_SUCCESS, ret);
}

HWTEST_F(ProfileCacheTest, DeleteServiceProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    int32_t ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().DeleteServiceProfile(devId, serName);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

HWTEST_F(ProfileCacheTest, DeleteCharProfile_001, TestSize.Level2)
{
    std::string devId = "";
    std::string serName = "";
    std::string charKey = "";
    int32_t ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "dp_serName";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    charKey = "dp_charKey";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_SUCCESS, ret);
    
    devId = "";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    serName = "";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);

    devId = "dp_devId";
    ret = ProfileCache::GetInstance().DeleteCharProfile(devId, serName, charKey);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
}

HWTEST_F(ProfileCacheTest, IsDeviceProfileExist_001, TestSize.Level2)
{
    DeviceProfile deviceProfile;
    bool ret = ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile);
    EXPECT_EQ(false, ret);
    
    std::string devId = "dp_devId";
    deviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile);
    EXPECT_EQ(false, ret);

    DeviceProfile deviceProfile1;
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
    ret = ProfileCache::GetInstance().IsDeviceProfileExist(deviceProfile1);
    EXPECT_EQ(true, ret);
}

HWTEST_F(ProfileCacheTest, IsServiceProfileExist_001, TestSize.Level2)
{
    ServiceProfile serviceProfile;
    bool ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);
    
    std::string devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);
    
    devId = "";
    std::string serName = "dp_serName";
    serviceProfile.SetDeviceId(devId);
    serviceProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);
    
    devId = "dp_devId";
    serviceProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile);
    EXPECT_EQ(false, ret);

    ServiceProfile serviceProfile1;
    serviceProfile1.SetDeviceId("deviceId1");
    serviceProfile1.SetServiceName("serviceName1");
    serviceProfile1.SetServiceType("serviceType1");
    ProfileCache::GetInstance().AddServiceProfile(serviceProfile1);
    ret = ProfileCache::GetInstance().IsServiceProfileExist(serviceProfile1);
    EXPECT_EQ(true, ret);
}

HWTEST_F(ProfileCacheTest, IsCharProfileExist_001, TestSize.Level2)
{
    CharacteristicProfile charProfile;
    bool ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    std::string devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    std::string serName = "dp_serName";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    devId = "";
    charProfile.SetDeviceId(devId);
    std::string charKey = "dp_charKey";
    charProfile.SetCharacteristicKey(charKey);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);
    
    serName = "";
    charProfile.SetServiceName(serName);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);

    devId = "dp_devId";
    charProfile.SetDeviceId(devId);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile);
    EXPECT_EQ(false, ret);

    CharacteristicProfile charProfile1;
    charProfile1.SetDeviceId("deviceId1");
    charProfile1.SetServiceName("serviceName1");
    charProfile1.SetCharacteristicKey("characteristicKey1");
    charProfile1.SetCharacteristicValue("characteristicValue1");
    ProfileCache::GetInstance().AddCharProfile(charProfile1);
    ret = ProfileCache::GetInstance().IsCharProfileExist(charProfile1);
    EXPECT_EQ(true, ret);
}

HWTEST_F(ProfileCacheTest, RefreshCharProfileCache_001, TestSize.Level2)
{
    std::vector<CharacteristicProfile> characteristicProfiles;
    int32_t ret = ProfileCache::GetInstance().RefreshCharProfileCache(characteristicProfiles);
    EXPECT_EQ(DP_INVALID_PARAMS, ret);
    
    CharacteristicProfile characteristicProfile;
    std::string devId = "dp_devId";
    std::string serName = "dp_serName";
    std::string charKey = "dp_charKey";
    characteristicProfile.SetDeviceId(devId);
    characteristicProfile.SetServiceName(serName);
    characteristicProfile.SetCharacteristicKey(charKey);
    characteristicProfiles.push_back(characteristicProfile);
    ret = ProfileCache::GetInstance().RefreshCharProfileCache(characteristicProfiles);
    EXPECT_EQ(DP_SUCCESS, ret);
}

/**
 * @tc.name: AddSyncListener001
 * @tc.desc: AddSyncListener all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, AddSyncListener001, TestSize.Level1)
{
    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
    string caller = "caller";
    OHOS::sptr<OHOS::IRemoteObject> syncListener = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallback());
    
    int32_t ret1 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_SUCCESS, ret1);
    
    for (int32_t i = 0; i < MAX_LISTENER_SIZE + 5; i++) {
        string caller = "caller" + std::to_string(i);
        OHOS::sptr<OHOS::IRemoteObject> syncListener1 = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallback());
        ProfileCache::GetInstance().syncListenerMap_[caller] = syncListener1;
    }
    int32_t ret2 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_EXCEED_MAX_SIZE_FAIL, ret2);

    syncListener = nullptr;
    int32_t ret3 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_INVALID_PARAMS, ret3);

    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        caller += 'a';
    }
    int32_t ret4 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_INVALID_PARAMS, ret4);
    
    caller = "";
    int32_t ret5 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_INVALID_PARAMS, ret5);
    
    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
}

/**
 * @tc.name: RemoveSyncListeners001
 * @tc.desc: RemoveSyncListeners all.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, RemoveSyncListeners001, TestSize.Level1)
{
    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
    ProfileCache::GetInstance().syncListenerMap_.clear();

    string caller = "caller";
    OHOS::sptr<OHOS::IRemoteObject> syncListener = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallback());
    
    int32_t ret1 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_SUCCESS, ret1);

    map<string, sptr<IRemoteObject>> syncListeners;
    syncListeners[caller] = syncListener;
    int32_t ret2 = ProfileCache::GetInstance().RemoveSyncListeners(syncListeners);
    EXPECT_EQ(DP_SUCCESS, ret2);

    ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    auto iter = ProfileCache::GetInstance().syncListenerMap_.begin();
    iter->second = nullptr;
    ProfileCache::GetInstance().RemoveSyncListeners(syncListeners);
    bool ret3 = ProfileCache::GetInstance().syncListenerMap_.count(caller);
    EXPECT_EQ(false, ret3);

    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
}

/**
 * @tc.name: RemoveSyncListener001
 * @tc.desc: RemoveSyncListener overload1.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, RemoveSyncListener001, TestSize.Level1)
{
    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
    ProfileCache::GetInstance().syncListenerMap_.clear();

    string caller = "caller";
    OHOS::sptr<OHOS::IRemoteObject> syncListener = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallback());
    
    int32_t ret1 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_SUCCESS, ret1);

    int32_t ret2 = ProfileCache::GetInstance().RemoveSyncListener(caller);
    EXPECT_EQ(DP_SUCCESS, ret2);

    int32_t ret3 = ProfileCache::GetInstance().RemoveSyncListener(caller);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret3);
    
    for (int32_t i = 0; i < MAX_STRING_LEN + 5; i++) {
        caller += 'a';
    }
    int32_t ret4 = ProfileCache::GetInstance().RemoveSyncListener(caller);
    EXPECT_EQ(DP_INVALID_PARAMS, ret4);
    
    caller = "";
    int32_t ret5 = ProfileCache::GetInstance().RemoveSyncListener(caller);
    EXPECT_EQ(DP_INVALID_PARAMS, ret5);

    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
}

/**
 * @tc.name: RemoveSyncListener002
 * @tc.desc: RemoveSyncListener overload2.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, RemoveSyncListener002, TestSize.Level1)
{
    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
    ProfileCache::GetInstance().syncListenerMap_.clear();

    string caller = "caller";
    OHOS::sptr<OHOS::IRemoteObject> syncListener = OHOS::sptr<SyncCompletedCallbackStub>(new SyncCallback());
    
    int32_t ret1 = ProfileCache::GetInstance().AddSyncListener(caller, syncListener);
    EXPECT_EQ(DP_SUCCESS, ret1);

    int32_t ret2 = ProfileCache::GetInstance().RemoveSyncListener(syncListener);
    EXPECT_EQ(DP_SUCCESS, ret2);

    int32_t ret4 = ProfileCache::GetInstance().RemoveSyncListener(syncListener);
    EXPECT_EQ(DP_NOT_FOUND_FAIL, ret4);

    syncListener = nullptr;
    int32_t ret5 = ProfileCache::GetInstance().RemoveSyncListener(syncListener);
    EXPECT_EQ(DP_INVALID_PARAMS, ret5);

    ProfileCache::GetInstance().UnInit();
    ProfileCache::GetInstance().Init();
}

/**
 * @tc.name: OnNodeOnline001
 * @tc.desc: OnNodeOnline001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, OnNodeOnline001, TestSize.Level1)
{
    std::string peerNetworkId = "NetworkId";
    std::string peerUdid = "peerUdid";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    deviceInfo.SetUdid(peerUdid);
    deviceInfo.SetUuid("peerUuid");
    deviceInfo.SetAuthForm(1);
    deviceInfo.SetOsType(10);
    ProfileCache::GetInstance().OnNodeOnline(deviceInfo);
    EXPECT_EQ(peerNetworkId, ProfileCache::GetInstance().onlineDevMap_[peerUdid].GetNetworkId());
    ProfileCache::GetInstance().onlineDevMap_.clear();
}

/**
 * @tc.name: OnNodeOffline001
 * @tc.desc: OnNodeOffline001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, OnNodeOffline001, TestSize.Level1)
{
    std::string peerNetworkId = "NetworkId";
    std::string peerUdid = "peerUdid";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(peerNetworkId);
    deviceInfo.SetUdid(peerUdid);
    ProfileCache::GetInstance().onlineDevMap_[peerUdid] = deviceInfo;
    ProfileCache::GetInstance().OnNodeOffline(peerNetworkId);
    EXPECT_EQ(true, ProfileCache::GetInstance().onlineDevMap_.empty());
}

/**
 * @tc.name: FilterAndGroupOnlineDevices001
 * @tc.desc: FilterAndGroupOnlineDevices failed, deviceList.size() == 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, FilterAndGroupOnlineDevices001, TestSize.Level1)
{
    vector<std::string> deviceList;
    std::vector<std::string> ohBasedDevices;
    std::vector<std::string> notOHBasedDevices;
    bool res = ProfileCache::GetInstance().FilterAndGroupOnlineDevices(deviceList, ohBasedDevices, notOHBasedDevices);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: FilterAndGroupOnlineDevices002
 * @tc.desc: FilterAndGroupOnlineDevices failed, deviceList.size() > MAX_DEVICE_SIZE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, FilterAndGroupOnlineDevices002, TestSize.Level1)
{
    vector<std::string> deviceList;
    for (int32_t i = 0; i < MAX_DEVICE_SIZE + 5; i++) {
        deviceList.emplace_back("networkId");
    }
    std::vector<std::string> ohBasedDevices;
    std::vector<std::string> notOHBasedDevices;
    bool res = ProfileCache::GetInstance().FilterAndGroupOnlineDevices(deviceList, ohBasedDevices, notOHBasedDevices);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: FilterAndGroupOnlineDevices003
 * @tc.desc: FilterAndGroupOnlineDevices failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, FilterAndGroupOnlineDevices003, TestSize.Level1)
{
    TrustedDeviceInfo deviceInfo1;
    deviceInfo1.SetNetworkId("networkId1");
    deviceInfo1.SetUdid("udid1");
    deviceInfo1.SetOsType(OHOS_TYPE);
    ProfileCache::GetInstance().onlineDevMap_[deviceInfo1.GetUdid()] = deviceInfo1;
    TrustedDeviceInfo deviceInfo2;
    deviceInfo2.SetNetworkId("networkId2");
    deviceInfo2.SetUdid("udid2");
    deviceInfo2.SetOsType(OHOS_TYPE_UNKNOWN);
    ProfileCache::GetInstance().onlineDevMap_[deviceInfo2.GetUdid()] = deviceInfo2;

    
    std::vector<std::string> deviceList {deviceInfo1.GetNetworkId(), deviceInfo2.GetNetworkId()};
    std::vector<std::string> ohBasedDevices;
    std::vector<std::string> notOHBasedDevices;
    bool res = ProfileCache::GetInstance().FilterAndGroupOnlineDevices(deviceList, ohBasedDevices, notOHBasedDevices);
    EXPECT_TRUE(res);
    EXPECT_FALSE(ohBasedDevices.empty());
    EXPECT_FALSE(notOHBasedDevices.empty());
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceInfo1.GetUdid());
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceInfo2.GetUdid());
}

/**
 * @tc.name: AddAllTrustedDevices001
 * @tc.desc: AddAllTrustedDevices001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, AddAllTrustedDevices001, TestSize.Level1)
{
    std::vector<TrustedDeviceInfo> deviceInfos;
    int32_t ret = ProfileCache::GetInstance().AddAllTrustedDevices(deviceInfos);
    EXPECT_EQ(ret, DP_INVALID_PARAM);
}

/**
 * @tc.name: AddAllTrustedDevices002
 * @tc.desc: AddAllTrustedDevices002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, AddAllTrustedDevices002, TestSize.Level1)
{
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId("peerNetworkId");
    deviceInfo.SetUdid("udid");
    deviceInfo.SetUuid("peerUuid");
    deviceInfo.SetAuthForm(1);
    deviceInfo.SetOsType(10);
    std::vector<TrustedDeviceInfo> deviceInfos {deviceInfo};
    int32_t ret = ProfileCache::GetInstance().AddAllTrustedDevices(deviceInfos);
    EXPECT_EQ(ret, DP_SUCCESS);
    EXPECT_FALSE(ProfileCache::GetInstance().onlineDevMap_.empty());
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceInfo.GetUdid());
}

/**
 * @tc.name: IsDeviceOnline001
 * @tc.desc: IsDeviceOnline001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, IsDeviceOnline001, TestSize.Level1)
{
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetUdid("udid");
    ProfileCache::GetInstance().onlineDevMap_[deviceInfo.GetUdid()] = deviceInfo;
    EXPECT_TRUE(ProfileCache::GetInstance().IsDeviceOnline());
    ProfileCache::GetInstance().onlineDevMap_.erase(deviceInfo.GetUdid());
}

/**
 * @tc.name: IsDeviceOnline002
 * @tc.desc: IsDeviceOnline002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, IsDeviceOnline002, TestSize.Level1)
{
    ProfileCache::GetInstance().onlineDevMap_.clear();
    EXPECT_FALSE(ProfileCache::GetInstance().IsDeviceOnline());
}

/**
 * @tc.name: GetStaticCharacteristicProfile001
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile001, TestSize.Level1)
{
    std::string deviceId = "";
    std::string serviceName = "";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile002
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile002, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile003
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile003, TestSize.Level1)
{
    std::string deviceId = "";
    std::string serviceName = "serviceName";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile004
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile004, TestSize.Level1)
{
    std::string deviceId = "";
    std::string serviceName = "";
    std::string charKey = "charKey";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile005
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile005, TestSize.Level1)
{
    std::string deviceId = "";
    std::string serviceName = "serviceName";
    std::string charKey = "charKey";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile006
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile006, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "";
    std::string charKey = "charKey";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile007
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile007, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string charKey = "";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetStaticCharacteristicProfile008
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile008, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string charKey = "charKey";
    CharacteristicProfile charProfile;
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_NOT_FOUND_FAIL);
}

/**
 * @tc.name: GetStaticCharacteristicProfile009
 * @tc.desc: GetStaticCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetStaticCharacteristicProfile009, TestSize.Level1)
{
    std::string deviceId = "deviceId";
    std::string serviceName = "serviceName";
    std::string charKey = "charKey";
    CharacteristicProfile charProfile;
    std::string charProfileKey =
        CHAR_PREFIX + SEPARATOR + deviceId + SEPARATOR + serviceName + SEPARATOR + charKey;
    ProfileCache::GetInstance().staticCharProfileMap_.emplace(charProfileKey, charProfile);
    int32_t ret =
        ProfileCache::GetInstance().GetStaticCharacteristicProfile(deviceId, serviceName, charKey, charProfile);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: RefreshStaticProfileCache001
 * @tc.desc: RefreshStaticProfileCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, RefreshStaticProfileCache001, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> staticProfiles;
    int32_t ret = ProfileCache::GetInstance().RefreshStaticProfileCache(staticProfiles);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: RefreshStaticProfileCache002
 * @tc.desc: RefreshStaticProfileCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, RefreshStaticProfileCache002, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> staticProfiles;
    staticProfiles.reserve(10001);
    for (int i = 0; i < 100001; ++i) {
        std::string key = "key_" + std::to_string(i);
        CharacteristicProfile profile;
        staticProfiles[key] = profile;
    }
    int32_t ret = ProfileCache::GetInstance().RefreshStaticProfileCache(staticProfiles);
    staticProfiles.clear();
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: RefreshStaticProfileCache003
 * @tc.desc: RefreshStaticProfileCache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, RefreshStaticProfileCache003, TestSize.Level1)
{
    std::unordered_map<std::string, CharacteristicProfile> staticProfiles;
    CharacteristicProfile charProfile;
    std::string charProfileKey = "charProfileKey";
    staticProfiles.emplace(charProfileKey, charProfile);
    int32_t ret = ProfileCache::GetInstance().RefreshStaticProfileCache(staticProfiles);
    staticProfiles.clear();
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetNetWorkIdByUdid001
 * @tc.desc: GetNetWorkIdByUdid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetNetWorkIdByUdid001, TestSize.Level1)
{
    std::string udid = "";
    std::string networkId = "";
    int32_t ret = ProfileCache::GetInstance().GetNetWorkIdByUdid(udid, networkId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: GetNetWorkIdByUdid002
 * @tc.desc: GetNetWorkIdByUdid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetNetWorkIdByUdid002, TestSize.Level1)
{
    std::string udid = "udid1";
    std::string networkId = "";
    ContentSensorManagerUtils::GetInstance().localUdid_ = "udid1";
    int32_t ret = ProfileCache::GetInstance().GetNetWorkIdByUdid(udid, networkId);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetNetWorkIdByUdid003
 * @tc.desc: GetNetWorkIdByUdid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetNetWorkIdByUdid003, TestSize.Level1)
{
    std::string udid = "udid1";
    std::string networkId = "";
    int32_t ret = ProfileCache::GetInstance().GetNetWorkIdByUdid(udid, networkId);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: GetNetWorkIdByUdid004
 * @tc.desc: GetNetWorkIdByUdid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, GetNetWorkIdByUdid004, TestSize.Level1)
{
    std::string udid = "udid1";
    std::string networkId = "networkId";
    TrustedDeviceInfo deviceInfo;
    deviceInfo.SetNetworkId(networkId);
    deviceInfo.SetUdid(udid);
    deviceInfo.SetUuid("peerUuid");
    deviceInfo.SetAuthForm(1);
    deviceInfo.SetOsType(10);
    ProfileCache::GetInstance().onlineDevMap_[udid] = deviceInfo;
    int32_t ret = ProfileCache::GetInstance().GetNetWorkIdByUdid(udid, networkId);
    EXPECT_EQ(ret, DP_SUCCESS);
    ProfileCache::GetInstance().onlineDevMap_.erase(udid);
}

/**
 * @tc.name: SetSwitchByProfileBatch001
 * @tc.desc: SetSwitchByProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, SetSwitchByProfileBatch001, TestSize.Level1)
{
    std::vector<CharacteristicProfile> charProfiles;
    std::unordered_map<std::string, SwitchFlag> switchServiceMap;
    uint32_t outSwitch;
    int32_t ret = ProfileCache::GetInstance().SetSwitchByProfileBatch(charProfiles, switchServiceMap, outSwitch);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}


/**
 * @tc.name: SetSwitchByProfileBatch002
 * @tc.desc: SetSwitchByProfileBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProfileCacheTest, SetSwitchByProfileBatch002, TestSize.Level1)
{
    std::vector<CharacteristicProfile> charProfiles;
    std::unordered_map<std::string, SwitchFlag> switchServiceMap;
    uint32_t outSwitch;
    CharacteristicProfile charProfile;
    int32_t ret = ProfileCache::GetInstance().SetSwitchByProfileBatch(charProfiles, switchServiceMap, outSwitch);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS

