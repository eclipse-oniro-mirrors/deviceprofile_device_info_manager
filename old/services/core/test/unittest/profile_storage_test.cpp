/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define private public
#define protected public
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage.h"
#include "device_profile_storage_manager.h"
#include "distributed_device_profile_client.h"
#include "hisysevent.h"
#include "nlohmann/json.hpp"
#include "online_sync_table.h"
#include "sync_coordinator.h"
#include "syscap_info_collector.h"
#include "syscap_interface.h"
#undef private
#undef protected

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::HiviewDFX;
using namespace OHOS::DistributedKv;
namespace {
    const std::string TAG = "SyscapInfoCollector";
    const std::string SERVICE_ID = "test";
    const std::string SERVICE_TYPE = "test";
    const std::string CHARACTER_PRIVATE_SYSCAP = "privatesyscap";
    const std::string CHARACTER_OS_SYSCAP = "ossyscap";
    const std::string FAULT_CODE_KEY = "FAULT_CODE";
    const std::string DOMAIN_NAME = std::string(HiSysEvent::Domain::DEVICE_PROFILE);
    const std::string APP_ID = "distributed_device_profile_service";
    const std::string STORE_ID = "online_sync_storage_test";
    static std::shared_ptr<DeviceProfileStorage> deviceProfileStorage = nullptr;
    static std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_ = nullptr;
}
using namespace testing;
using namespace testing::ext;

class ProfileStorageTest : public testing::Test {
public:
    ProfileStorageTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

ProfileStorageTest::ProfileStorageTest()
{
    DTEST_LOG << "constructor" << std::endl;
}

void ProfileStorageTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
    std::string baseDir = "/data/service/el1/public/database/test";
    mkdir(baseDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .securityLevel = DistributedKv::SecurityLevel::S1,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .area = 1,
        .baseDir = baseDir
    };
    // clean the IMMEDIATE_SYNC_ON_CHANGE
    SyncPolicy syncPolicy {
        .type = PolicyType::IMMEDIATE_SYNC_ON_ONLINE
    };
    options.policies.emplace_back(syncPolicy);
    deviceProfileStorage = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    if (deviceProfileStorage != nullptr) {
        deviceProfileStorage->SetOptions(options);
    }
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

class ProfileSyncHandler : public DistributedKv::KvStoreSyncCallback {
public:
    void SyncCompleted(const std::map<std::string, DistributedKv::Status>& results) override
    {
    }
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
    /**
     * @tc.steps: step1. add RestoreServiceItemLocked
     */
    DeviceProfileStorageManager::GetInstance().RestoreServiceItemLocked("");
    
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
    /**
     * @tc.steps: step1. add SetServiceType_001
     */
    DeviceProfileStorageManager::GetInstance().SetServiceType("", "", profile);

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
    /**
     * @tc.steps: step1. add SetServiceType_002
     */
    std::string udid = "1111test1111";
    DeviceProfileStorageManager::GetInstance().SetServiceType(udid, "", profile);

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
    /**
     * @tc.steps: step1. add SetServiceType_003
     */
    ServiceCharacteristicProfile profile;
    std::string serviceId = "2222test2222";
    DeviceProfileStorageManager::GetInstance().SetServiceType("", serviceId, profile);

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
    /**
     * @tc.steps: step1. add SetServiceType_004
     */
    ServiceCharacteristicProfile profile;
    std::string udid = "1111test1111";
    std::string serviceId = "2222test2222";
    DeviceProfileStorageManager::GetInstance().SetServiceType(udid, serviceId, profile);

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
 * @tc.name: PutDeviceProfile_005
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_005, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    int32_t res = onlineSyncTbl_->PutDeviceProfile("test", "test");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
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
    int32_t result = DeviceProfileStorageManager::GetInstance().GetDeviceProfile("test", "", profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: GetDeviceProfile_004
 * @tc.desc: get device profile with syscap
 * @tc.type: FUNC
 * @tc.require: I59PZ3
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_004, TestSize.Level3)
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
 * @tc.name: DeleteDeviceProfile_003
 * @tc.desc: delete device profile with empty service id after init
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_003, TestSize.Level3)
{
    int32_t result = DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile("");
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: DeleteDeviceProfile_004
 * @tc.desc: put device profile batch
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_004, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    int32_t res = onlineSyncTbl_->DeleteDeviceProfile("test");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RemoveDeviceData_001
 * @tc.desc: put device profile batch
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RemoveDeviceData_001, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    int32_t res = onlineSyncTbl_->RemoveDeviceData("networkid11111");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_002
 * @tc.desc: SubscribeKvStore
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_002, TestSize.Level3)
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
 * @tc.name: RegisterSyncCallback_002
 * @tc.desc: RegisterSyncCallback
 * @tc.type: FUNC
 * @tc.require: I4NY21
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_002, TestSize.Level3)
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
 * @tc.name: SyncDeviceProfile_002
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
    EXPECT_EQ(ERR_DP_SUBSCRIBE_FAILED, result);
}

/**
 * @tc.name: SyncDeviceProfile_003
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileStorageTest, SyncDeviceProfile_003, TestSize.Level3)
{
    wptr<IRemoteObject> remote;
    DistributedDeviceProfileClient::DeviceProfileDeathRecipient obj;
    obj.OnRemoteDied(remote);
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    syncCb = nullptr;
    SyncOptions syncOptions;
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    notifier = nullptr;
    int result = DeviceProfileStorageManager::GetInstance().SyncDeviceProfile(syncOptions, notifier);
    EXPECT_EQ(ERR_DP_SUBSCRIBE_FAILED, result);
}

/**
 * @tc.name: RemoveUnBoundDeviceProfile_003
 * @tc.desc: remove unBound device profile
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RemoveUnBoundDeviceProfile_003, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    int32_t result = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("");
    EXPECT_EQ(ERR_DP_GET_NETWORKID_FAILED, result);
}

/**
 * @tc.name: RemoveUnBoundDeviceProfile_004
 * @tc.desc: remove unBound device profile
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RemoveUnBoundDeviceProfile_004, TestSize.Level3)
{
    std::string event = "EVENT_TEST";
    std::string key = "EVENT_KEY";
    int32_t result = 0;
    std::string strResult = "returnresult";
    DeviceProfileStorageManager::GetInstance().DumpLocalProfile(strResult);
    DeviceProfileStorageManager::GetInstance().ReportFaultEvent(event, key, result);
    DeviceProfileStorageManager::GetInstance().ReportBehaviorEvent(event);
    result = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("test");
    EXPECT_EQ(ERR_DP_GET_NETWORKID_FAILED, result);
}

/**
 * @tc.name: CheckSyncOption_001
 * @tc.desc: report fault event
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, CheckSyncOption_001, TestSize.Level3)
{
    SyncOptions syncOptions;
    std::string deviceId = "1111test2222";
    syncOptions.AddDevice(deviceId);
    DeviceProfileStorageManager::GetInstance().NotifySyncCompleted();
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    DeviceProfileStorageManager::GetInstance().NotifySubscriberDied(notifier);
    notifier = nullptr;
    DeviceProfileStorageManager::GetInstance().NotifySubscriberDied(notifier);
    bool res = DeviceProfileStorageManager::GetInstance().CheckSyncOption(syncOptions);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: SubscribeKvStore_003
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_003, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ = nullptr;
    int32_t res = onlineSyncTbl_->SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: GetDeviceProfile_005
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_005, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::string key = "";
    std::string value = "";
    int32_t res = onlineSyncTbl_->GetDeviceProfile(key, value);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: GetDeviceProfile_006
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_006, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::string key = "";
    std::string udid = "";
    std::string value = "";
    int32_t res = onlineSyncTbl_->GetDeviceProfile(udid, key, value);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: GetDeviceProfile_006
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_007, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::string key = "11111";
    std::string udid = "";
    std::string value = "";
    int32_t res = onlineSyncTbl_->GetDeviceProfile(udid, key, value);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: GetDeviceProfile_006
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_008, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::string key = "";
    std::string udid = "111111";
    std::string value = "";
    int32_t res = onlineSyncTbl_->GetDeviceProfile(udid, key, value);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: GetDeviceProfile_006
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, GetDeviceProfile_009, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::string key = "11111";
    std::string udid = "11111";
    std::string value = "";
    int32_t res = onlineSyncTbl_->GetDeviceProfile(udid, key, value);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_004
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_004, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = onlineSyncTbl_->SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_002
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_002, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ = nullptr;
    int32_t res = onlineSyncTbl_->UnSubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_003
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_003, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = onlineSyncTbl_->UnSubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RegisterSyncCallback_003
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_003, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback = nullptr;
    int32_t res = onlineSyncTbl_->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RegisterSyncCallback_004
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_004, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback =
      std::make_shared<ProfileSyncHandler>();
    int32_t res = onlineSyncTbl_->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(0, res);
}

/**
 * @tc.name: UnRegisterSyncCallback_002
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnRegisterSyncCallback_002, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    int32_t res = onlineSyncTbl_->UnRegisterSyncCallback();
    EXPECT_EQ(0, res);
}

/**
 * @tc.name: GetKvStore_001
 * @tc.desc: get kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, GetKvStore_001, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->DeleteKvStore();
    int32_t res = onlineSyncTbl_->GetKvStore();
    EXPECT_EQ(27459585, res);
}

/**
 * @tc.name: PutDeviceProfile_006
 * @tc.desc: get device profile
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_006, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    int32_t res = onlineSyncTbl_->PutDeviceProfile("test", "test");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_005
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_005, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = onlineSyncTbl_->SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_006
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_006, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ = nullptr;
    int32_t res = onlineSyncTbl_->SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_004
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_004, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = onlineSyncTbl_->UnSubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_005
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_005, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ = nullptr;
    int32_t res = onlineSyncTbl_->UnSubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RegisterSyncCallback_005
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_005, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback =
      std::make_shared<ProfileSyncHandler>();
    int32_t res = onlineSyncTbl_->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(0, res);
}

/**
 * @tc.name: RegisterSyncCallback_006
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_006, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback = nullptr;
    int32_t res = onlineSyncTbl_->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnRegisterSyncCallback_003
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnRegisterSyncCallback_003, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    int32_t res = onlineSyncTbl_->UnRegisterSyncCallback();
    EXPECT_EQ(0, res);
}

/**
 * @tc.name: PutDeviceProfileBatch_001
 * @tc.desc: put device profile batch
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfileBatch_001, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    vector<std::string> keys = {"test"};
    vector<std::string> values = {"test"};
    int32_t res = onlineSyncTbl_->PutDeviceProfileBatch(keys, values);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: DeleteDeviceProfile_005
 * @tc.desc: put device profile batch
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_005, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    int32_t res = onlineSyncTbl_->DeleteDeviceProfile("test");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RemoveDeviceData_002
 * @tc.desc: remove device data
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RemoveDeviceData_002, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    int32_t res = onlineSyncTbl_->RemoveDeviceData("network1111111");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: CheckTrustGroup_001
 * @tc.desc: check trust group
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, CheckTrustGroup_001, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::vector<std::string> deviceIdList = {};
    bool res = onlineSyncTbl_->CheckTrustGroup(deviceIdList);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: CheckTrustGroup_002
 * @tc.desc: check trust group
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, CheckTrustGroup_002, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<OnlineSyncTable>();
    std::vector<std::string> deviceIdList = {"did1111111"};
    bool res = onlineSyncTbl_->CheckTrustGroup(deviceIdList);
    EXPECT_EQ(false, res);
}

/**
 * @tc.name: SubscribeKvStore_007
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_007, TestSize.Level2)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ = nullptr;
    int32_t res = DeviceProfileStorageManager::GetInstance().SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_006
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_006, TestSize.Level2)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ = nullptr;
    DeviceProfileStorageManager::GetInstance().profileItems_.clear();
    DeviceProfileStorageManager::GetInstance().FlushProfileItems();
    int32_t res = DeviceProfileStorageManager::GetInstance().UnSubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: DeleteDeviceProfile_006
 * @tc.desc: delete device profile with empty service id after init
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_006, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    DeviceProfileStorageManager::GetInstance().servicesJson_.clear();
    int32_t result = DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile("test");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: DeleteDeviceProfile_007
 * @tc.desc: delete device profile with empty service id after init
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_007, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    nlohmann::json j;
    j[SERVICE_TYPE] = "567";
    DeviceProfileStorageManager::GetInstance().servicesJson_["test"] = j;
    int32_t result = DeviceProfileStorageManager::GetInstance().DeleteDeviceProfile("test");
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: PutDeviceProfile_007
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_007, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("");
    profile.SetServiceType("test");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    int32_t result = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: RegisterSyncCallback_007
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_007, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback =
      std::make_shared<ProfileSyncHandler>();
    std::shared_ptr<OnlineSyncTable> onlineSyncTblTest_ = std::make_shared<OnlineSyncTable>();
    std::map<std::string, DistributedKv::Status> results;
    onlineSyncTblTest_->syncCallback_ = nullptr;
    onlineSyncTblTest_->NotifySyncCompleted(results);
    onlineSyncTblTest_->syncCallback_ = syncCallback;
    onlineSyncTblTest_->NotifySyncCompleted(results);
    SyncCoordinator::GetInstance().isOnlineTrigger_ = true;
    onlineSyncTblTest_->SyncCompleted(results);
    SyncCoordinator::GetInstance().isOnlineTrigger_ = false;
    onlineSyncTblTest_->SyncCompleted(results);
    bool result = onlineSyncTblTest_->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: AcquireSync_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, AcquireSync_001, TestSize.Level3)
{
    SyncCoordinator::GetInstance().isOnSync_ = true;
    bool result = SyncCoordinator::GetInstance().AcquireSync();
    EXPECT_EQ(false, result);
}

/**
 * @tc.name: UnRegisterSyncCallback_004
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, UnRegisterSyncCallback_004, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    int32_t result = onlineSyncTbl_->UnRegisterSyncCallback();
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: UnRegisterSyncCallback_005
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, UnRegisterSyncCallback_005, TestSize.Level3)
{
    deviceProfileStorage->Init();
    if (deviceProfileStorage != nullptr) {
        int32_t result = deviceProfileStorage->UnRegisterSyncCallback();
        EXPECT_EQ(0, result);
    }
}

/**
 * @tc.name: PutDeviceProfile_008
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_008, TestSize.Level3)
{
    deviceProfileStorage->Init();
    ServiceCharacteristicProfile profile;
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    std::vector<std::string> keys;
    std::vector<std::string> values;
    keys.emplace_back(DeviceProfileStorageManager::GetInstance().GenerateKey("test123udid", "test", KeyType::SERVICE));
    values.emplace_back(profile.GetCharacteristicProfileJson());
    if (deviceProfileStorage->kvStorePtr_ == nullptr) {
        deviceProfileStorage->kvStorePtr_ = kvStorePtr_;
    }
    if (deviceProfileStorage != nullptr) {
        int32_t result = deviceProfileStorage->PutDeviceProfile(keys[0], values[0]);
        EXPECT_EQ(0, result);
    }
}

/**
 * @tc.name: PutDeviceProfileBatch_002
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfileBatch_002, TestSize.Level3)
{
    deviceProfileStorage->Init();
    std::vector<std::string> keys;
    std::vector<std::string> values;
    keys.emplace_back("key");
    values.emplace_back("value1");
    values.emplace_back("value2");
    if (deviceProfileStorage != nullptr) {
        int32_t result = deviceProfileStorage->PutDeviceProfileBatch(keys, values);
        EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
    }
}

/**
 * @tc.name: DeleteDeviceProfile_008
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, DeleteDeviceProfile_008, TestSize.Level3)
{
    deviceProfileStorage->Init();
    std::string key =
        DeviceProfileStorageManager::GetInstance().GenerateKey("test123udid", "test", KeyType::SERVICE);
    if (deviceProfileStorage != nullptr) {
        int32_t result = deviceProfileStorage->DeleteDeviceProfile(key);
        EXPECT_EQ(0, result);
    }
}

/**
 * @tc.name: SubscribeKvStore_008
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_008, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    int32_t res = onlineSyncTbl_->SubscribeKvStore(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_009
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_009, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = onlineSyncTbl_->SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_0010
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_0010, TestSize.Level3)
{
    deviceProfileStorage->Init();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = deviceProfileStorage->SubscribeKvStore(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: SubscribeKvStore_0011
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, SubscribeKvStore_0011, TestSize.Level3)
{
    deviceProfileStorage->Init();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = deviceProfileStorage->SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(0, res);
}

/**
 * @tc.name: UnSubscribeKvStore_007
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_007, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    int32_t res = onlineSyncTbl_->UnSubscribeKvStore(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_008
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_008, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = onlineSyncTbl_->UnSubscribeKvStore(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_009
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_009, TestSize.Level3)
{
    deviceProfileStorage->Init();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = deviceProfileStorage->UnSubscribeKvStore(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: UnSubscribeKvStore_0010
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, UnSubscribeKvStore_0010, TestSize.Level3)
{
    deviceProfileStorage->Init();
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    int32_t res = deviceProfileStorage->UnSubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(27459590, res);
}

/**
 * @tc.name: RegisterSyncCallback_008
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_008, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    int32_t res = onlineSyncTbl_->RegisterSyncCallback(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RegisterSyncCallback_009
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_009, TestSize.Level2)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback =
      std::make_shared<ProfileSyncHandler>();
    int32_t res = onlineSyncTbl_->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RegisterSyncCallback_010
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_010, TestSize.Level2)
{
    deviceProfileStorage->Init();
    int32_t res = deviceProfileStorage->RegisterSyncCallback(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}

/**
 * @tc.name: RegisterSyncCallback_011
 * @tc.desc: subscribe kvstore
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RegisterSyncCallback_011, TestSize.Level2)
{
    deviceProfileStorage->Init();
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback =
      std::make_shared<ProfileSyncHandler>();
    int32_t res = deviceProfileStorage->RegisterSyncCallback(syncCallback);
    EXPECT_EQ(0, res);
}

/**
 * @tc.name: RemoveDeviceData_003
 * @tc.desc: remove device data
 * @tc.type: FUNC
 * @tc.require: I4OH93
 */
HWTEST_F(ProfileStorageTest, RemoveDeviceData_003, TestSize.Level2)
{
    deviceProfileStorage->Init();
    int32_t res = deviceProfileStorage->RemoveDeviceData("network1111111");
    EXPECT_EQ(27459585, res);
}

/**
 * @tc.name: SyncDeviceProfile_004
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileStorageTest, SyncDeviceProfile_004, TestSize.Level3)
{
    deviceProfileStorage->Init();
    DeviceProfileStorageManager::GetInstance().RegisterCallbacks();
    DeviceProfileStorageManager::GetInstance().kvStoreObserver_ = std::make_shared<DistributedKv::KvStoreObserver>();
    std::vector<std::string> deviceIds = {"", std::move("testudid123"), ""};
    int result = deviceProfileStorage->SyncDeviceProfile(deviceIds, SyncMode::PUSH);
    EXPECT_EQ(ERR_DP_UNTRUSTED_GROUP, result);
}

/**
 * @tc.name: PutDeviceProfile_009
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_009, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    ServiceCharacteristicProfile profile;
    profile.SetServiceId("testttt");
    profile.SetServiceType("testttt");
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    nlohmann::json j1;
    j1["type"] = "testttt";
    DeviceProfileStorageManager::GetInstance().servicesJson_["testttt"] = j1;
    int32_t result = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, result);
}

/**
 * @tc.name: SetServiceType_005
 * @tc.desc: set service type
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, SetServiceType_005, TestSize.Level3)
{
    deviceProfileStorage->Init();
    ServiceCharacteristicProfile profile;
    nlohmann::json j;
    j["testVersion"] = "3.0.0";
    j["testApiLevel"] = 8;
    profile.SetCharacteristicProfileJson(j.dump());
    std::vector<std::string> keys;
    std::vector<std::string> values;
    keys.emplace_back(DeviceProfileStorageManager::GetInstance().GenerateKey(
        "test123udid", "services", KeyType::SERVICE_LIST));
    values.emplace_back(profile.GetCharacteristicProfileJson());
    int result = -1;
    if (deviceProfileStorage->kvStorePtr_ == nullptr) {
        deviceProfileStorage->kvStorePtr_ = kvStorePtr_;
    }
    if (deviceProfileStorage != nullptr) {
        result = deviceProfileStorage->PutDeviceProfile(keys[0], values[0]);
    }
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_ = deviceProfileStorage;
    
    std::string udid = "test123udid";
    std::string serviceId = "test";
    DeviceProfileStorageManager::GetInstance().SetServiceType(udid, serviceId, profile);
    std::shared_ptr<DistributedKv::KvStoreSyncCallback> syncCallback =
        std::make_shared<ProfileSyncHandler>();
    DeviceProfileStorageManager::GetInstance().kvStoreObserver_ = std::make_shared<DistributedKv::KvStoreObserver>();
    DeviceProfileStorageManager::GetInstance().kvStoreSyncCallback_ = syncCallback;
    DeviceProfileStorageManager::GetInstance().RegisterCallbacks();
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: PutDeviceProfile_010
 * @tc.desc: put device profile nullptr
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, PutDeviceProfile_010, TestSize.Level3)
{
    ServiceCharacteristicProfile profile;
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    int32_t ret = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_EQ(ret, ERR_OK);
    DeviceProfileStorageManager::GetInstance().kvDataServiceFailed_ = true;
    ret = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_NE(ret, ERR_OK);
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_FAILED;
    ret = DeviceProfileStorageManager::GetInstance().PutDeviceProfile(profile);
    EXPECT_NE(ret, ERR_OK);
    ret = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("111");
    EXPECT_NE(ret, ERR_OK);
    ret = DeviceProfileStorageManager::GetInstance().RemoveRemoteDeviceProfile();
    EXPECT_NE(ret, ERR_OK);
    std::shared_ptr<DistributedKv::KvStoreObserver> kvStoreObserver_ =
        std::make_shared<DistributedKv::KvStoreObserver>();
    ret = DeviceProfileStorageManager::GetInstance().SubscribeKvStore(kvStoreObserver_);
    EXPECT_EQ(ret, ERR_OK);
    DeviceProfileStorageManager::GetInstance().RegisterCallbacks();
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ = StorageInitStatus::INIT_SUCCEED;
    ret = DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile("111");
    EXPECT_NE(ret, ERR_OK);
    ret = DeviceProfileStorageManager::GetInstance().RemoveRemoteDeviceProfile();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: DeviceProfileStorage_001
 * @tc.desc: onlineSyncTbl_ nullptr
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, DeviceProfileStorage_001, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    onlineSyncTbl_->kvStoreInitCallback_ = nullptr;
    onlineSyncTbl_->Init();
    onlineSyncTbl_->kvStorePtr_ = nullptr;
    bool ret = onlineSyncTbl_->TryGetKvStore();
    EXPECT_EQ(ret, false);
}

void MyKvStoreInitCallback()
{
    return;
} 

/**
 * @tc.name: RegisterKvStoreInitCallback_001
 * @tc.desc: onlineSyncTbl_ nullptr
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileStorageTest, RegisterKvStoreInitCallback_001, TestSize.Level3)
{
    std::shared_ptr<DeviceProfileStorage> onlineSyncTbl_ = std::make_shared<DeviceProfileStorage>(APP_ID, STORE_ID);
    onlineSyncTbl_->kvStoreInitCallback_ = nullptr;
    DeviceProfileStorage::KvStoreInitCallback callback;
    onlineSyncTbl_->RegisterKvStoreInitCallback(MyKvStoreInitCallback);
    bool ret = onlineSyncTbl_->RegisterKvStoreInitCallback(MyKvStoreInitCallback);
    EXPECT_EQ(ret, false);
}
}
}