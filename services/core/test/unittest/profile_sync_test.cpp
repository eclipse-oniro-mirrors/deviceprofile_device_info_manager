/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "distributed_device_profile_service.h"
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
}
using namespace testing;
using namespace testing::ext;

class ProfileSyncTest : public testing::Test {
public:
    ProfileSyncTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

public:
    std::shared_ptr<DeviceProfileStorage> deviceProfileStorage;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
};

ProfileSyncTest::ProfileSyncTest()
{
}

void ProfileSyncTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileSyncTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileSyncTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileSyncTest::TearDown()
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
 * @tc.name: Init_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileSyncTest, Init_001, TestSize.Level3)
{
    auto runner = AppExecFwk::EventRunner::Create("dpstoragetest");
    DeviceProfileStorageManager::GetInstance().storageHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(runner);
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_ =
        std::make_shared<OnlineSyncTable>();
    DeviceProfileStorageManager::GetInstance().inited_ = true;
    bool result = DeviceProfileStorageManager::GetInstance().Init();
    EXPECT_EQ(true, result);
}
/**
 * @tc.name: RegisterSyncCallback_001
 * @tc.desc: put device profile with empty service id
 * @tc.type: FUNC
 * @tc.require: I4NY23
 */
HWTEST_F(ProfileSyncTest, RegisterSyncCallback_001, TestSize.Level3)
{
    DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->initStatus_ =
        StorageInitStatus::INIT_SUCCEED;
    int32_t res = DeviceProfileStorageManager::GetInstance().RegisterSyncCallback(nullptr);
    EXPECT_EQ(ERR_DP_INVALID_PARAMS, res);
}
/**
 * @tc.name: SyncDeviceProfile_001
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileSyncTest, SyncDeviceProfile_001, TestSize.Level3)
{
    SyncCoordinator::GetInstance().Init();
    std::vector<std::string> deviceIds = {"", std::move("testudid123"), ""};
    std::map<std::string, Status> results;
    results["123456"] = Status::SUCCESS;
    results["78910"] = Status::ERROR;
    results["996"] = Status::ERROR;
    std::list<std::vector<std::string>> deviceIdsList_;
    std::vector<std::string> vectorDeviceId = {"996", "996", "996"};
    deviceIdsList_.push_back(vectorDeviceId);
    DpDeviceManager::GetInstance().deviceIdsList_ = deviceIdsList_;
    SyncCoordinator::GetInstance().isOnlineTrigger_ = true;
    std::shared_ptr<OnlineSyncTable> onlineSyncTblTest_ = std::make_shared<OnlineSyncTable>();
    onlineSyncTblTest_->SyncCompleted(results);
    int result = DeviceProfileStorageManager::GetInstance().onlineSyncTbl_->
        SyncDeviceProfile(deviceIds, SyncMode::PUSH);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: DeleteDeviceProfile_001
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileSyncTest, DeleteDeviceProfile_001, TestSize.Level3)
{
    int32_t res = DistributedDeviceProfileService::GetInstance().DeleteDeviceProfile("test");
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, res);
}

/**
 * @tc.name: SyncDeviceProfile_002
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileSyncTest, SyncDeviceProfile_002, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    SyncOptions syncOptions;
    sptr<IRemoteObject> notifier =
        sptr<ProfileEventNotifierStub>(new ProfileEventNotifierStub(syncCb));
    int result = DistributedDeviceProfileService::GetInstance().SyncDeviceProfile(syncOptions, notifier);
    EXPECT_EQ(ERR_DP_PERMISSION_DENIED, result);
}

/**
 * @tc.name: OnIdle_001
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileSyncTest, OnIdle_001, TestSize.Level3)
{
    DistributedDeviceProfileService::GetInstance().isOnline_ = true;
    auto runner = AppExecFwk::EventRunner::Create("unload");
    DistributedDeviceProfileService::GetInstance().unloadHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedDeviceProfileService::GetInstance().DelayUnloadTask();
    SystemAbilityOnDemandReason reason;
    reason.SetId(OnDemandReasonId::SETTING_SWITCH);
    int result = DistributedDeviceProfileService::GetInstance().OnIdle(reason);
    EXPECT_EQ(0, result);
}

/**
 * @tc.name: OnIdle_002
 * @tc.desc: sync device profile
 * @tc.type: FUNC
 * @tc.require: I5QPGN
 */
HWTEST_F(ProfileSyncTest, OnIdle_002, TestSize.Level3)
{
    SystemAbilityOnDemandReason reason;
    reason.SetId(OnDemandReasonId::DEVICE_ONLINE);
    SyncCoordinator::GetInstance().isOnSync_ = false;
    int result = DistributedDeviceProfileService::GetInstance().OnIdle(reason);
    EXPECT_EQ(0, result);
}
}
}