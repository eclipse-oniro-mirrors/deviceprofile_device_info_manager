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

#include "sync_completed_callback_proxy.h"
#include "distributed_device_profile_log.h"
#include "macro_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "SyncCompletedCallbackProxy";
}
SyncCompletedCallbackProxy::SyncCompletedCallbackProxy(const sptr <IRemoteObject> &impl)
    : IRemoteProxy<ISyncCompletedCallback>(impl)
{
    HILOGI("constructor!");
}

void SyncCompletedCallbackProxy::OnSyncCompleted(const SyncResult &syncResults) {
    HILOGI("called");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(SyncCompletedCallbackProxy::GetDescriptor())) {
        HILOGE("write descriptor failed");
        return;
    }
    if (!data.WriteInt32(static_cast<int32_t>(syncResults.size()))) {
        HILOGE("write syncResults size failed");
        return;
    }

    for (const auto&[deviceId, syncResult]: syncResults) {
        if (!data.WriteString(deviceId) ||
            !data.WriteInt32(static_cast<int32_t>(syncResult))) {
            HILOGE("write syncResults failed");
            return;
        }
    }
    MessageOption option{MessageOption::TF_ASYNC};
    int32_t errCode = Remote()->SendRequest(static_cast<uint32_t>(DPInterfaceCode::ON_SYNC_COMPLETED), data, reply,
        option);
    if (errCode != ERR_OK) {
        HILOGE("send request failed, errCode = %{public}d", errCode);
    }
}
} // namespace DistributedDeviceProfile
} // namespace OHOS