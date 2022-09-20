/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "profile_event_notifier_stub.h"

#include <iosfwd>
#include <string>
#include <utility>

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "errors.h"
#include "ipc_object_stub.h"
#include "iprofile_event_callback.h"
#include "message_parcel.h"
#include "profile_change_notification.h"
#include "profile_event.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "ProfileEventNotifierStub";
}

const ProfileEventNotifierStub::HandlersMap ProfileEventNotifierStub::handlersMap_ =
    ProfileEventNotifierStub::InitHandlersMap();

ProfileEventNotifierStub::HandlersMap ProfileEventNotifierStub::InitHandlersMap()
{
    ProfileEventNotifierStub::HandlersMap m;
    m[EVENT_SYNC_COMPLETED] = &ProfileEventNotifierStub::OnSyncCompletedInner;
    m[EVENT_PROFILE_CHANGED] = &ProfileEventNotifierStub::OnProfileChangedInner;
    return m;
}

int32_t ProfileEventNotifierStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u", code);
    std::u16string descriptor = ProfileEventNotifierStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOGE("check descriptor failed");
        return ERR_DP_INTERFACE_CHECK_FAILED;
    }

    auto iter = handlersMap_.find(code);
    if (iter != handlersMap_.end()) {
        auto handler = iter->second;
        if (handler != nullptr) {
            return (this->*handler)(data, reply);
        }
    }
    HILOGW("unknown request code, please check");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ProfileEventNotifierStub::OnSyncCompletedInner(MessageParcel& data,
    [[maybe_unused]] MessageParcel& reply)
{
    int32_t size = data.ReadInt32();
    if (size <= 0) {
        HILOGW("size %{public}d", size);
        return ERR_DP_INVALID_PARAMS;
    }

    SyncResult syncResults;
    for (int32_t i = 0; i < size; i++) {
        syncResults.emplace(data.ReadString(), static_cast<SyncStatus>(data.ReadInt32()));
    }
    if (profileEventCb_ != nullptr) {
        profileEventCb_->OnSyncCompleted(syncResults);
    }
    return ERR_OK;
}

int32_t ProfileEventNotifierStub::OnProfileChangedInner(MessageParcel& data,
    [[maybe_unused]] MessageParcel& reply)
{
    ProfileChangeNotification changeNotification;
    if (!changeNotification.Unmarshalling(data)) {
        HILOGW("marshalling failed");
        return ERR_DP_INVALID_PARAMS;
    }
    profileEventCb_->OnProfileChanged(changeNotification);
    return ERR_OK;
}
} // namespace DeviceProfile
} // namespace OHOS