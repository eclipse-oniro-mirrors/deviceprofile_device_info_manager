/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "device_profile_storage_manager.h"
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
    const std::string SERVICE_ID = "test";
    const std::string SERVICE_TYPE = "test";
    const std::string CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
    const std::string CHARACTER_OS_SYSCAP = "ossyscap";
    const std::string DEVICE_PROFILE_SYNC_FAILED = "DEVICE_PROFILE_SYNC_FAILED";
    const std::string FAULT_CODE_KEY = "FAULT_CODE";
    const std::string DOMAIN_NAME = std::string(HiSysEvent::Domain::DEVICE_PROFILE);
}
using namespace testing;
using namespace testing::ext;

class ProfileStorageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ProfileStorageTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileStorageTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileStorageTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileStorageTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

class StorageProfileEventCallback : public IProfileEventCallback {
};

/**
 * @tc.name: TryGetKvStore_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, TryGetKvStore_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    bool result = DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->TryGetKvStore();
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    int32_t result = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INIT_DB_FAILED, result);
}

/**
 * @tc.name: GetDeviceProfile_001
 * @tc.desc: get device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    int32_t result = DeviceProfileStorageManager::GetInstance().GetDeviceProfile("", "", profile);
    EXPECT_EQ(ERR_DP_INIT_DB_FAILED, result);
}

/**
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: delete device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_001, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile("");
    EXPECT_EQ(ERR_DP_INIT_DB_FAILED, result);
}

/**
 * @tc.name: RemoveUnBoundDeviceProfile_001
 * @tc.desc: delete device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RemoveUnBoundDeviceProfile_001, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("");
    EXPECT_EQ(ERR_DP_INIT_DB_FAILED, result);
}

/**
 * @tc.name: SyncDeviceProfile_001
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileStorageTest, SyncDeviceProfile_001, TestSize.Level3)
{
    wptr<IRemoteObject> remote;
    DistributedDeviceProfileClient::DeviceProfileDeathRecipient obj;
    obj.OnRemoteDied(remote);
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    SyncOptions syncOptions;
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    int result = DeviceProfileStorageManager::GetInstance().SyncDeviceProfile(syncOptions, notifier);
    EXPECT_EQ(ERR_DP_INIT_DB_FAILED, result);
}

/**
 * @tc.name: RestoreServiceItemLocked_001
 * @tc.desc: RestoreServiceItemLocked
 * @tc.type: FUNC
 * @tc.require: I4NY1U
 */
HWTEST_F(ProfileStorageTest, RestoreServiceItemLocked_001, TestSize.Level3)
{
    int result = 0;
    DeviceProfileStorageManager::GetInstance().RestoreServiceItemLocked("");
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, SetServiceType_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    int result = 0;
    DeviceProfileStorageManager::GetInstance().SetServiceType("", "", profile);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: PutDeviceProfile_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, WaitKvDataService_001, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    bool result = DeviceProfileStorageManager::GetInstance().WaitKvDataService();
    EXPECT_EQ(true, result);
}

/**
 * @tc.name: RemoveUnBoundDeviceProfile_002
 * @tc.desc: delete device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RemoveUnBoundDeviceProfile_002, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::UNINITED;
    int32_t result = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("");
    EXPECT_EQ(ERR_DP_NOT_INIT_DB, result);
}

/**
 * @tc.name: Init_001
 * @tc.desc: get device profile with syscap
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ProfileStorageTest, Init_001, TestSize.Level3)
{
    bool result = DeviceProfileStorageManager::GetInstance().Init();
    EXPECT_EQ(true, result);
    sleep(2);
}

/**
 * @tc.name: PutDeviceProfile_002
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_002, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: PutDeviceProfile_003
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_003, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: PutDeviceProfile_004
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_004, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("test");
    profile.SetServiceType("");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: GetDeviceProfile_002
 * @tc.desc: get device profile with syscap
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_002, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    int32_t result = DeviceProfileStorageManager::GetInstance().GetDeviceProfile("", SERVICE_ID, profile);
    EXPECT_EQ(0, result);
    std::string jsonData = profile.GetCharacteristicProfileJson();
    DTEST_LOG << "jsonData:" << jsonData << std::endl;
}

/**
 * @tc.name: GetDeviceProfile_003
 * @tc.desc: get device profile with syscap
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_003, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    profile.SetServiceId(SERVICE_ID);
    profile.SetServiceType(SERVICE_TYPE);
    int32_t result = DeviceProfileStorageManager::GetInstance().GetDeviceProfile("test", SERVICE_ID, profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: DeleteDeviceProfile_002
 * @tc.desc: delete an empty profile
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_002, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile("test");
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: SubscribeKvStore_001
 * @tc.desc: SubscribeKvStore
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_001, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().SubscribeKvStore(nullptr);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: UnSubscribeKvStore_001
 * @tc.desc: UnSubscribeKvStore
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_001, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().UnSubscribeKvStore(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: RegisterSyncCallback_001
 * @tc.desc: RegisterSyncCallback
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_001, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().RegisterSyncCallback(nullptr);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: UnRegisterSyncCallback_001
 * @tc.desc: UnRegisterSyncCallback
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, UnRegisterSyncCallback_001, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().UnRegisterSyncCallback();
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: SyncDeviceProfile_003
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileStorageTest, SyncDeviceProfile_002, TestSize.Level3)
{
    wptr<IRemoteObject> remote;
    DistributedDeviceProfileClient::DeviceProfileDeathRecipient obj;
    obj.OnRemoteDied(remote);
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    SyncOptions syncOptions;
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    int result = DeviceProfileStorageManager::GetInstance().SyncDeviceProfile(syncOptions, notifier);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: RemoveUnBoundDeviceProfile_003
 * @tc.desc: delete device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RemoveUnBoundDeviceProfile_003, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("");
    EXPECT_EQ(ERR_DP_NOT_INIT_DB, result);
}
}
}