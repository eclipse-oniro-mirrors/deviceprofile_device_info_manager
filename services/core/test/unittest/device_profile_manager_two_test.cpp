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

void DeviceProfileManagerTwoTest::SetUpTestCase(void)
{}

void DeviceProfileManagerTwoTest::TearDownTestCase(void)
{}

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

void DeviceProfileManagerTwoTest::TearDown()
{}

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

/**
* @tc.name: DeleteBatchByKeys001
* @tc.desc: DeleteBatchByKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, DeleteBatchByKeys001, TestSize.Level1)
{
    std::vector<std::string> delKeys;
    int ret = DeviceProfileManager::GetInstance().DeleteBatchByKeys(delKeys);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
* @tc.name: DeleteBatchByKeys002
* @tc.desc: DeleteBatchByKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, DeleteBatchByKeys002, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("key1", "value1"));
    entries.insert(std::make_pair("key2", "value2"));
    DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);

    std::vector<std::string> delKeys = {"key1", "key2"};
    int ret = DeviceProfileManager::GetInstance().DeleteBatchByKeys(delKeys);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
* @tc.name: DeleteBatchByKeys003
* @tc.desc: DeleteBatchByKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, DeleteBatchByKeys003, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("key3", "value3"));
    entries.insert(std::make_pair("key4", "value4"));
    DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);

    std::vector<std::string> delKeys = {"test_key1", "test_key2"};
    int ret = DeviceProfileManager::GetInstance().DeleteBatchByKeys(delKeys);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
* @tc.name: DeleteBatchByKeys004
* @tc.desc: DeleteBatchByKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, DeleteBatchByKeys004, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("key5", "value5"));
    entries.insert(std::make_pair("key6", "value6"));
    DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);

    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    std::vector<std::string> delKeys = {"key5", "key6"};
    int ret = DeviceProfileManager::GetInstance().DeleteBatchByKeys(delKeys);
    EXPECT_EQ(ret, DP_KV_DB_PTR_NULL);
}

/**
* @tc.name: DeleteBatchByKeys005
* @tc.desc: DeleteBatchByKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, DeleteBatchByKeys005, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("key7", "value7"));
    entries.insert(std::make_pair("key8", "value8"));
    DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);

    std::vector<std::string> delKeys = {"key7", "key8"};
    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int ret = DeviceProfileManager::GetInstance().DeleteBatchByKeys(delKeys);
    EXPECT_EQ(ret, DP_DEL_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: DeleteBatchByKeys006
* @tc.desc: DeleteBatchByKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, DeleteBatchByKeys006, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    entries.insert(std::make_pair("key9", "value9"));
    entries.insert(std::make_pair("key10", "value10"));
    DeviceProfileManager::GetInstance().SaveBatchByKeys(entries);

    std::vector<std::string> delKeys = {"key9", "key10"};
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    int ret = DeviceProfileManager::GetInstance().DeleteBatchByKeys(delKeys);
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: SavePutTempCache001
* @tc.desc: SavePutTempCache
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, SavePutTempCache001, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    int ret = DeviceProfileManager::GetInstance().SavePutTempCache(entries);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
* @tc.name: SavePutTempCache002
* @tc.desc: SavePutTempCache
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, SavePutTempCache002, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key1", "value1"));
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key2", "value2"));

    int ret = DeviceProfileManager::GetInstance().SavePutTempCache(entries);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
* @tc.name: SavePutTempCache003
* @tc.desc: SavePutTempCache
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, SavePutTempCache003, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key3", "value3"));
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key4", "value4"));
    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;

    int ret = DeviceProfileManager::GetInstance().SavePutTempCache(entries);
    EXPECT_EQ(ret, DP_GET_KV_DB_FAIL);
}

/**
* @tc.name: SavePutTempCache004
* @tc.desc: SavePutTempCache
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, SavePutTempCache004, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key5", "value5"));
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key6", "value6"));

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int ret = DeviceProfileManager::GetInstance().SavePutTempCache(entries);
    EXPECT_EQ(ret, DP_KV_DB_PTR_NULL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: SavePutTempCache005
* @tc.desc: SavePutTempCache
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, SavePutTempCache005, TestSize.Level1)
{
    std::map<std::string, std::string> entries;
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key7", "value7"));
    DeviceProfileManager::GetInstance().putTempCache_.insert(std::make_pair("key8", "value8"));

    DeviceProfileManager::GetInstance().isFirst_.store(true);
    int ret = DeviceProfileManager::GetInstance().SavePutTempCache(entries);
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: PutCharacteristicProfileBatch001
* @tc.desc: PutCharacteristicProfileBatch
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, PutCharacteristicProfileBatch001, TestSize.Level1)
{
    CharacteristicProfile charProfile1;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceId1";
    charProfile1.SetDeviceId("deviceId1");
    charProfile1.SetServiceName("serviceName1");
    charProfile1.SetCharacteristicKey("characteristicKey1");
    charProfile1.SetCharacteristicValue("characteristicValue1");
    charProfile1.isMultiUser_ = false;

    CharacteristicProfile charProfile2;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceId2";
    charProfile2.SetDeviceId("deviceId2");
    charProfile2.SetServiceName("serviceName2");
    charProfile2.SetCharacteristicKey("characteristicKey2");
    charProfile2.SetCharacteristicValue("characteristicValue2");
    charProfile2.isMultiUser_ = false;

    CharacteristicProfile charProfile3;
    ContentSensorManagerUtils::GetInstance().localUdid_ = "deviceId3";
    charProfile3.SetDeviceId("deviceId3");
    charProfile3.SetServiceName("serviceName3");
    charProfile3.SetCharacteristicKey("characteristicKey3");
    charProfile3.SetCharacteristicValue("characteristicValue3");
    charProfile3.isMultiUser_ = false;

    std::vector<CharacteristicProfile> charProfiles1;
    charProfiles1.emplace_back(charProfile1);
    charProfiles1.emplace_back(charProfile2);
    charProfiles1.emplace_back(charProfile3);

    int ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles1);
    EXPECT_EQ(ret, DP_SUCCESS);
}

/**
* @tc.name: PutCharacteristicProfileBatch002
* @tc.desc: PutCharacteristicProfileBatch
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, PutCharacteristicProfileBatch002, TestSize.Level1)
{
    CharacteristicProfile charProfile4;
    charProfile4.SetDeviceId("");
    charProfile4.SetServiceName("serviceName4");
    charProfile4.SetCharacteristicKey("characteristicKey4");
    charProfile4.SetCharacteristicValue("characteristicValue4");

    CharacteristicProfile charProfile5;
    charProfile5.SetDeviceId("");
    charProfile5.SetServiceName("serviceName5");
    charProfile5.SetCharacteristicKey("characteristicKey5");
    charProfile5.SetCharacteristicValue("characteristicValue5");

    CharacteristicProfile charProfile6;
    charProfile6.SetDeviceId("");
    charProfile6.SetServiceName("serviceName6");
    charProfile6.SetCharacteristicKey("characteristicKey6");

    std::vector<CharacteristicProfile> charProfiles2;
    charProfiles2.emplace_back(charProfile4);
    charProfiles2.emplace_back(charProfile5);
    charProfiles2.emplace_back(charProfile6);

    int ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles2);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
}

/**
* @tc.name: PutCharacteristicProfileBatch003
* @tc.desc: PutCharacteristicProfileBatch
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, PutCharacteristicProfileBatch003, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    CharacteristicProfile charProfile7;
    charProfile7.SetDeviceId(deviceId);
    charProfile7.SetServiceName("serviceName7");
    charProfile7.SetCharacteristicKey("characteristicKey7");
    charProfile7.SetCharacteristicValue("characteristicValue7");
    charProfile7.isMultiUser_ = false;

    CharacteristicProfile charProfile8;
    charProfile8.SetDeviceId(deviceId);
    charProfile8.SetServiceName("serviceName8");
    charProfile8.SetCharacteristicKey("characteristicKey8");
    charProfile8.SetCharacteristicValue("characteristicValue8");
    charProfile8.isMultiUser_ = false;

    CharacteristicProfile charProfile9;
    charProfile9.SetDeviceId(deviceId);
    charProfile9.SetServiceName("serviceName9");
    charProfile9.SetCharacteristicKey("characteristicKey9");
    charProfile9.SetCharacteristicValue("characteristicValue9");
    charProfile9.isMultiUser_ = false;

    std::vector<CharacteristicProfile> charProfiles3;
    charProfiles3.emplace_back(charProfile7);
    charProfiles3.emplace_back(charProfile8);
    charProfiles3.emplace_back(charProfile9);

    int ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles3);
    EXPECT_EQ(ret, DP_SUCCESS);

    DeviceProfileManager::GetInstance().deviceProfileStore_ = nullptr;
    ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles3);
    EXPECT_EQ(ret, DP_KV_DB_PTR_NULL);
}

/**
* @tc.name: PutCharacteristicProfileBatch004
* @tc.desc: PutCharacteristicProfileBatch
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, PutCharacteristicProfileBatch004, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    CharacteristicProfile charProfile10;
    charProfile10.SetDeviceId(deviceId);
    charProfile10.SetServiceName("serviceName10");
    charProfile10.SetCharacteristicKey("characteristicKey10");
    charProfile10.SetCharacteristicValue("characteristicValue10");
    charProfile10.isMultiUser_ = false;

    CharacteristicProfile charProfile11;
    charProfile11.SetDeviceId(deviceId);
    charProfile11.SetServiceName("serviceName11");
    charProfile11.SetCharacteristicKey("characteristicKey11");
    charProfile11.SetCharacteristicValue("characteristicValue11");
    charProfile11.isMultiUser_ = false;

    CharacteristicProfile charProfile12;
    charProfile12.SetDeviceId(deviceId);
    charProfile12.SetServiceName("serviceName12");
    charProfile12.SetCharacteristicKey("characteristicKey12");
    charProfile12.SetCharacteristicValue("characteristicValue12");
    charProfile12.isMultiUser_ = false;

    std::vector<CharacteristicProfile> charProfiles4;
    charProfiles4.emplace_back(charProfile10);
    charProfiles4.emplace_back(charProfile11);
    charProfiles4.emplace_back(charProfile12);

    DeviceProfileManager::GetInstance().deviceProfileStore_->UnInit();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles4);
    EXPECT_EQ(ret, DP_PUT_KV_DB_FAIL);
    DeviceProfileManager::GetInstance().Init();
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: PutCharacteristicProfileBatch005
* @tc.desc: PutCharacteristicProfileBatch
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, PutCharacteristicProfileBatch005, TestSize.Level1)
{
    string deviceId = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    CharacteristicProfile charProfile13;
    charProfile13.SetDeviceId(deviceId);
    charProfile13.SetServiceName("serviceName13");
    charProfile13.SetCharacteristicKey("characteristicKey13");
    charProfile13.SetCharacteristicValue("characteristicValue13");
    charProfile13.isMultiUser_ = false;

    CharacteristicProfile charProfile14;
    charProfile14.SetDeviceId(deviceId);
    charProfile14.SetServiceName("serviceName14");
    charProfile14.SetCharacteristicKey("characteristicKey14");
    charProfile14.SetCharacteristicValue("characteristicValue14");
    charProfile14.isMultiUser_ = false;

    CharacteristicProfile charProfile15;
    charProfile15.SetDeviceId(deviceId);
    charProfile15.SetServiceName("serviceName15");
    charProfile15.SetCharacteristicKey("characteristicKey15");
    charProfile15.SetCharacteristicValue("characteristicValue15");
    charProfile15.isMultiUser_ = false;

    std::vector<CharacteristicProfile> charProfiles5;
    charProfiles5.emplace_back(charProfile13);
    charProfiles5.emplace_back(charProfile14);
    charProfiles5.emplace_back(charProfile15);

    DeviceProfileManager::GetInstance().isFirst_.store(true);
    int32_t ret = DeviceProfileManager::GetInstance().PutCharacteristicProfileBatch(charProfiles5);
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: GetAllDeviceProfile004
* @tc.desc: GetAllDeviceProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, GetAllDeviceProfile004, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    std::vector<DeviceProfile> deviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllDeviceProfile(deviceProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: GetAllServiceProfile004
* @tc.desc: GetAllServiceProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, GetAllServiceProfile004, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    vector<ServiceProfile> serviceProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllServiceProfile(serviceProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}

/**
* @tc.name: GetAllCharacteristicProfile004
* @tc.desc: GetAllCharacteristicProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DeviceProfileManagerTwoTest, GetAllCharacteristicProfile004, TestSize.Level1)
{
    DeviceProfileManager::GetInstance().isFirst_.store(true);
    vector<CharacteristicProfile> charProfiles;
    int32_t ret = DeviceProfileManager::GetInstance().GetAllCharacteristicProfile(charProfiles);
    EXPECT_EQ(ret, DP_SUCCESS);
    DeviceProfileManager::GetInstance().isFirst_.store(false);
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
