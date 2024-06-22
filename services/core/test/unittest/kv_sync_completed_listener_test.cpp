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

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <iostream>

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"
#include "event_handler_factory.h"
#define private public
#define protected public

#include "listener/kv_sync_completed_listener.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "KvSyncCompletedListenerTest";
}
class KvSyncCompletedListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KvSyncCompletedListenerTest::SetUpTestCase()
{
}

void KvSyncCompletedListenerTest::TearDownTestCase()
{
}

void KvSyncCompletedListenerTest::SetUp()
{
}

void KvSyncCompletedListenerTest::TearDown()
{
}

/*
 * @tc.name: ~KvSyncCompletedListener001
 * @tc.desc: ~KvSyncCompletedListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KvSyncCompletedListenerTest, KvSyncCompletedListener001, TestSize.Level1)
{
    const std::string kvDeathHandler = "kv_store_death_handler";
    KvSyncCompletedListener KvSyncCompletedListener_;
    EventHandlerFactory EventHandlerFactory_;
    KvSyncCompletedListener_.onSyncHandler_ = EventHandlerFactory::GetInstance().CreateEventHandler(kvDeathHandler);
    EXPECT_EQ(EventHandlerFactory_.eventHandlerMap_[kvDeathHandler], KvSyncCompletedListener_.onSyncHandler_);

    const std::map<std::string, DistributedKv::Status> results;
    KvSyncCompletedListener_.SyncCompleted(results);

    const SyncResults syncResults;
    KvSyncCompletedListener_.NotifySyncCompleted(syncResults);
}
}
}
