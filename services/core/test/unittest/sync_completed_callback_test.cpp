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

#include <sys/statvfs.h>
#include "gtest/gtest.h"
#include "message_parcel.h"
#include "i_sync_completed_callback.h"
#include "ipc_object_stub.h"
#include "iremote_stub.h"
#include "refbase.h"

#define private public
#define protected public
#include "sync_completed_callback_proxy.h"
#include "sync_completed_callback_stub.h"
#undef private
#undef protected

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace testing;
using namespace testing::ext;

class SyncCompletedCallbackStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SyncCompletedCallbackStubTest::SetUpTestCase()
{
}

void SyncCompletedCallbackStubTest::TearDownTestCase()
{
}

void SyncCompletedCallbackStubTest::SetUp()
{
}

void SyncCompletedCallbackStubTest::TearDown()
{
}

class SyncCompletedListener : public SyncCompletedCallbackStub {
public:
    SyncCompletedListener()
    {
    }
    ~SyncCompletedListener()
    {
    }
    void OnSyncCompleted(const SyncResult& syncResults) override
    {
        return;
    }
};

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SyncCompletedCallbackStubTest, OnRemoteRequest_001, TestSize.Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    SyncResult syncResults;
    syncResults.emplace("testdeviceid", SUCCEEDED);
    if (!data.WriteInterfaceToken(SyncCompletedCallbackStub::GetDescriptor())) {
        return;
    }
    if (!data.WriteInt32(static_cast<int32_t>(syncResults.size()))) {
        return;
    }

    for (const auto& [deviceId, syncResult] : syncResults) {
        if (!data.WriteString(deviceId) ||
            !data.WriteInt32(static_cast<int32_t>(syncResult))) {
            return;
        }
    }
    uint32_t code = 27;
    SyncCompletedListener syncCallBackStub;
    int32_t errCode = syncCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(errCode, DP_SUCCESS);
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest of profile event notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SyncCompletedCallbackStubTest, OnRemoteRequest_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    if (!data.WriteInterfaceToken(SyncCompletedCallbackStub::GetDescriptor())) {
        return;
    }
    uint32_t code = 1;
    SyncCompletedListener syncCallBackStub;
    int32_t errCode = syncCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(305, errCode);
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: OnRemoteRequest of profile event notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SyncCompletedCallbackStubTest, OnRemoteRequest_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option { MessageOption::TF_ASYNC };
    SyncResult syncResults;
    uint32_t code = 1;
    SyncCompletedListener syncCallBackStub;
    int32_t errCode = syncCallBackStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DP_INTERFACE_CHECK_FAILED, errCode);
}

/**
 * @tc.name: OnSyncCompleted_003
 * @tc.desc: OnSyncCompleted of profile event notification
 * @tc.type: FUNC
 * @tc.require: I4NY1T
 */
HWTEST_F(SyncCompletedCallbackStubTest, OnSyncCompleted_003, TestSize.Level3)
{
    sptr<SyncCompletedListener> stub(new SyncCompletedListener());
    sptr<SyncCompletedCallbackProxy> proxy(new SyncCompletedCallbackProxy(stub));
    SyncResult syncResults;
    syncResults.emplace("testdeviceid", SUCCEEDED);
    proxy->OnSyncCompleted(syncResults);
}
}
}