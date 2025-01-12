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
#define private public
#define protected public

#include "sync_subscriber_death_recipient.h"

#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace DistributedDeviceProfile {
using namespace std;
namespace {
    const std::string TAG = "SyncSubscriberDeathRecipientTest";
}
class SyncSubscriberDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SyncSubscriberDeathRecipientTest::SetUpTestCase()
{
}

void SyncSubscriberDeathRecipientTest::TearDownTestCase()
{
}

void SyncSubscriberDeathRecipientTest::SetUp()
{
}

void SyncSubscriberDeathRecipientTest::TearDown()
{
}

/*
 * @tc.name: OnRemoteDied001
 * @tc.desc: OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SyncSubscriberDeathRecipientTest, OnRemoteDied001, TestSize.Level1)
{
    const wptr<IRemoteObject> remote = nullptr;
    SyncSubscriberDeathRecipient subDeath_;
    subDeath_.OnRemoteDied(remote);
    EXPECT_EQ(remote, nullptr);
}

/*
 * @tc.name: OnRemoteDied002
 * @tc.desc: OnRemoteDied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SyncSubscriberDeathRecipientTest, OnRemoteDied002, TestSize.Level1)
{
    const wptr<IRemoteObject> remote;
    SyncSubscriberDeathRecipient subDeath_;
    subDeath_.OnRemoteDied(remote);
    EXPECT_EQ(remote, nullptr);
}
}
}
