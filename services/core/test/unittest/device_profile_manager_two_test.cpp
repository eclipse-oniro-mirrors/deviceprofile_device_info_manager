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

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include <string>
#include "gtest/gtest.h"
#include "refbase.h"
#include "iremote_stub.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_enums.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "content_sensor_manager_utils.h"
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

class DeviceProfileManagerTwoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DeviceProfileManagerTwoTest::SetUpTestCase(void) {
}

void DeviceProfileManagerTwoTest::TearDownTestCase(void) {
}

void DeviceProfileManagerTwoTest::SetUp()
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

void DeviceProfileManagerTwoTest::TearDown() {
}

class SyncCallback : public SyncCompletedCallbackStub {
public:
    void OnSyncCompleted(const map<string, SyncStatus>& syncResults) {
    }
};
    
/**
 * @tc.name: GetDeviceProfile001
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile001, TestSize.Level1)
{
    std::string deviceID = "deviceID";
    DeviceProfile deviceProfile;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
 * @tc.name: GetDeviceProfile002
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile002, TestSize.Level1)
{
    std::string deviceID = "";
    DeviceProfile deviceProfile;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_MULTI_USER_PROFILE_PARAMS_INVALID);
}

/**
 * @tc.name: GetDeviceProfile003
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile003, TestSize.Level1)
{
    std::string deviceID = "deviceID";
    DeviceProfile deviceProfile;
    deviceProfile.isMultiUser_ = true;
    deviceProfile.userId_ = DEFAULT_USER_ID;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_MULTI_USER_PROFILE_PARAMS_INVALID);
}

/**
 * @tc.name: GetDeviceProfile004
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile004, TestSize.Level1)
{
    std::string deviceID = "deviceID";
    DeviceProfile deviceProfile;
    deviceProfile.isMultiUser_ = false;
    deviceProfile.userId_ = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_MULTI_USER_PROFILE_PARAMS_INVALID);
}

/**
 * @tc.name: GetDeviceProfile005
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile005, TestSize.Level1)
{
    std::string deviceID = ProfileCache::GetInstance().GetLocalUdid();
    DeviceProfile deviceProfile;
    deviceProfile.isMultiUser_ = true;
    deviceProfile.userId_ = 1;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID);
}

/**
 * @tc.name: GetDeviceProfile006
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile006, TestSize.Level1)
{
    std::string deviceID = ProfileCache::GetInstance().GetLocalUdid();
    DeviceProfile deviceProfile;
    deviceProfile.isMultiUser_ = true;
    deviceProfile.userId_ = 200;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID);
}

/**
 * @tc.name: GetDeviceProfile007
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile007, TestSize.Level1)
{
    std::string deviceID = ProfileCache::GetInstance().GetLocalUdid();
    DeviceProfile deviceProfile;
    deviceProfile.isMultiUser_ = true;
    deviceProfile.userId_ = 5;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID);
}

/**
 * @tc.name: GetDeviceProfile008
 * @tc.desc: GetDeviceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, GetDeviceProfile008, TestSize.Level1)
{
    std::string deviceID = ProfileCache::GetInstance().GetLocalUdid();
    DeviceProfile deviceProfile;
    deviceProfile.isMultiUser_ = true;
    deviceProfile.userId_ = 106;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().GetDeviceProfile(deviceID, deviceProfile);
    EXPECT_EQ(ret, DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID);
}

/**
 * @tc.name: DeleteServiceProfile001
 * @tc.desc: DeleteServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteServiceProfile001, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string serviceType = "serviceType";
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(localUdid);
    serviceProfile.SetServiceName(serviceName);
    serviceProfile.SetServiceType(serviceType);
    serviceProfile.SetIsMultiUser(true);
    serviceProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    
    std::string deviceId = "";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteServiceProfile002
 * @tc.desc: DeleteServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteServiceProfile002, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string serviceType = "serviceType";
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(localUdid);
    serviceProfile.SetServiceName(serviceName);
    serviceProfile.SetServiceType(serviceType);
    serviceProfile.SetIsMultiUser(true);
    serviceProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    
    std::string deviceId = "deviceId";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteServiceProfile003
 * @tc.desc: DeleteServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteServiceProfile003, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string serviceType = "serviceType";
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(localUdid);
    serviceProfile.SetServiceName(serviceName);
    serviceProfile.SetServiceType(serviceType);
    serviceProfile.SetIsMultiUser(true);
    serviceProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    
    std::string deviceId = localUdid;
    serviceName = "";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteServiceProfile004
 * @tc.desc: DeleteServiceProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteServiceProfile004, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string serviceType = "serviceType";
    ServiceProfile serviceProfile;
    serviceProfile.SetDeviceId(localUdid);
    serviceProfile.SetServiceName(serviceName);
    serviceProfile.SetServiceType(serviceType);
    serviceProfile.SetIsMultiUser(true);
    serviceProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutServiceProfile(serviceProfile);
    
    std::string deviceId = localUdid;
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: DeleteCharacteristicProfile001
 * @tc.desc: DeleteCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteCharacteristicProfile001, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    std::string characteristicValue = "characteristicValue";
    CharacteristicProfile characteristicProfile;
    characteristicProfile.SetDeviceId(localUdid);
    characteristicProfile.SetServiceName(serviceName);
    characteristicProfile.SetCharacteristicKey(characteristicKey);
    characteristicProfile.SetCharacteristicValue(characteristicValue);
    characteristicProfile.SetIsMultiUser(true);
    characteristicProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(characteristicProfile);
    
    std::string deviceId = localUdid;
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey,
        isMultiUser, userId);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
 * @tc.name: DeleteCharacteristicProfile002
 * @tc.desc: DeleteCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteCharacteristicProfile002, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    std::string characteristicValue = "characteristicValue";
    CharacteristicProfile characteristicProfile;
    characteristicProfile.SetDeviceId(localUdid);
    characteristicProfile.SetServiceName(serviceName);
    characteristicProfile.SetCharacteristicKey(characteristicKey);
    characteristicProfile.SetCharacteristicValue(characteristicValue);
    characteristicProfile.SetIsMultiUser(true);
    characteristicProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(characteristicProfile);
    
    std::string deviceId = "";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey,
        isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteCharacteristicProfile003
 * @tc.desc: DeleteCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteCharacteristicProfile003, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    std::string characteristicValue = "characteristicValue";
    CharacteristicProfile characteristicProfile;
    characteristicProfile.SetDeviceId(localUdid);
    characteristicProfile.SetServiceName(serviceName);
    characteristicProfile.SetCharacteristicKey(characteristicKey);
    characteristicProfile.SetCharacteristicValue(characteristicValue);
    characteristicProfile.SetIsMultiUser(true);
    characteristicProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(characteristicProfile);
    
    std::string deviceId = "deviceId";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey,
        isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteCharacteristicProfile004
 * @tc.desc: DeleteCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteCharacteristicProfile004, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    std::string characteristicValue = "characteristicValue";
    CharacteristicProfile characteristicProfile;
    characteristicProfile.SetDeviceId(localUdid);
    characteristicProfile.SetServiceName(serviceName);
    characteristicProfile.SetCharacteristicKey(characteristicKey);
    characteristicProfile.SetCharacteristicValue(characteristicValue);
    characteristicProfile.SetIsMultiUser(true);
    characteristicProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(characteristicProfile);
    
    std::string deviceId = localUdid;
    serviceName = "";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey,
        isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: DeleteCharacteristicProfile005
 * @tc.desc: DeleteCharacteristicProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, DeleteCharacteristicProfile005, TestSize.Level1)
{
    std::string localUdid = ProfileCache::GetInstance().GetLocalUdid();
    std::string serviceName = "serviceName";
    std::string characteristicKey = "characteristicKey";
    std::string characteristicValue = "characteristicValue";
    CharacteristicProfile characteristicProfile;
    characteristicProfile.SetDeviceId(localUdid);
    characteristicProfile.SetServiceName(serviceName);
    characteristicProfile.SetCharacteristicKey(characteristicKey);
    characteristicProfile.SetCharacteristicValue(characteristicValue);
    characteristicProfile.SetIsMultiUser(true);
    characteristicProfile.SetUserId(100);
    DeviceProfileManager::GetInstance().PutCharacteristicProfile(characteristicProfile);
    
    std::string deviceId = localUdid;
    characteristicKey = "";
    bool isMultiUser = true;
    int32_t userId = 100;
    int32_t ret = RET_INIT;
    ret = DeviceProfileManager::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey,
        isMultiUser, userId);
    EXPECT_EQ(ret, DP_INVALID_PARAMS);
}

/**
 * @tc.name: IsDeviceE2ESync001
 * @tc.desc: IsDeviceE2ESync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceProfileManagerTwoTest, IsDeviceE2ESync001, TestSize.Level1)
{
    ContentSensorManagerUtils::GetInstance().isDeviceE2ESync_.store(false);
    bool ret = DeviceProfileManager::GetInstance().IsDeviceE2ESync();
    EXPECT_EQ(ret, false);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
