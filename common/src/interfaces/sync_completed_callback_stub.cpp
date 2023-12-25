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

#include "sync_completed_callback_stub.h"

#include <iosfwd>
#include <string>
#include <utility>

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_constants.h"
#include "ipc_object_stub.h"
#include "message_parcel.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "SyncCompletedCallbackStub";
}

SyncCompletedCallbackStub::SyncCompletedCallbackStub()
{
    HILOGI("constructor!");
}

SyncCompletedCallbackStub::~SyncCompletedCallbackStub()
{
    HILOGI("destructor!");
}

int32_t SyncCompletedCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("Code = %{public}u", code);
    std::u16string descriptor = SyncCompletedCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOGE("Check descriptor failed");
        return DP_INTERFACE_CHECK_FAILED;
    }

    if (code != static_cast<uint32_t>(DPInterfaceCode::ON_SYNC_COMPLETED)) {
        HILOGW("Unknown request code, code = %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return OnSyncCompletedInner(data, reply);
}

int32_t SyncCompletedCallbackStub::OnSyncCompletedInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t size = data.ReadInt32();
    if (size <= 0 || size > MAX_SYNC_RESULTS_SIZE) {
        HILOGW("Size %{public}d", size);
        return DP_INVALID_PARAMS;
    }

    SyncResult syncResults;
    for (int32_t i = 0; i < size; i++) {
        syncResults.emplace(data.ReadString(), static_cast<SyncStatus>(data.ReadInt32()));
    }
    // send code handle cache
    OnSyncCompleted(syncResults);
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS

