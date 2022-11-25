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

#include <gtest/gtest.h>

#include "profile_event_notifier_proxy.h"
#include "distributed_device_profile_client.h"
#include "utils.h"

namespace OHOS {
namespace DeviceProfile {
using namespace testing;
using namespace testing::ext;

class ProfileEventNotifierProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class StorageProfileEventCallback : public IProfileEventCallback {
public:
    int result = 0;
};

void ProfileEventNotifierProxyTest::SetUpTestCase()
{
    DTEST_LOG << "SetUpTestCase" << std::endl;
}

void ProfileEventNotifierProxyTest::TearDownTestCase()
{
    DTEST_LOG << "TearDownTestCase" << std::endl;
}

void ProfileEventNotifierProxyTest::SetUp()
{
    DTEST_LOG << "SetUp" << std::endl;
}

void ProfileEventNotifierProxyTest::TearDown()
{
    DTEST_LOG << "TearDown" << std::endl;
}

/**
 * @tc.name: OnSyncCompleted_001
 * @tc.desc: OnSyncCompleted
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileEventNotifierProxyTest, OnSyncCompleted_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<ProfileEventNotifierStub> stub(new ProfileEventNotifierStub(syncCb));
    sptr<ProfileEventNotifierProxy> proxy(new ProfileEventNotifierProxy(stub));
    SyncResult syncResults;
    proxy->OnSyncCompleted(syncResults);
    EXPECT_EQ(syncCb->result, 0);
}

/**
 * @tc.name: OnSyncCompleted_001
 * @tc.desc: OnSyncCompleted
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileEventNotifierProxyTest, OnSyncCompleted_002, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<ProfileEventNotifierStub> stub(new ProfileEventNotifierStub(syncCb));
    sptr<ProfileEventNotifierProxy> proxy(new ProfileEventNotifierProxy(stub));
    SyncResult syncResults;
    syncResults.emplace("testdeviceid", SUCCEEDED);
    proxy->OnSyncCompleted(syncResults);
    EXPECT_EQ(syncCb->result, 0);
}

/**
 * @tc.name: OnProfileChanged_001
 * @tc.desc: OnProfileChanged
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(ProfileEventNotifierProxyTest, OnProfileChanged_001, TestSize.Level3)
{
    auto syncCb = std::make_shared<StorageProfileEventCallback>();
    sptr<ProfileEventNotifierStub> stub(new ProfileEventNotifierStub(syncCb));
    sptr<ProfileEventNotifierProxy> proxy(new ProfileEventNotifierProxy(stub));
    ProfileChangeNotification notification;
    proxy->OnProfileChanged(notification);
    EXPECT_EQ(syncCb->result, 0);
}
}
}