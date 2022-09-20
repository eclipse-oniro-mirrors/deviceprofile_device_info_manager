/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "distributed_device_profile_stub.h"

#include <string>

#include "authority_manager.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage.h"
#include "device_profile_utils.h"
#include "iprofile_event_notifier.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileStub";
constexpr uint32_t MAX_EVENT_LEN = 1000000;
}

DistributedDeviceProfileStub::DistributedDeviceProfileStub()
{
    funcsMap_[PUT_DEVICE_PROFILE] = &DistributedDeviceProfileStub::PutDeviceProfileInner;
    funcsMap_[DELETE_DEVICE_PROFILE] = &DistributedDeviceProfileStub::DeleteDeviceProfileInner;
    funcsMap_[GET_DEVICE_PROFILE] = &DistributedDeviceProfileStub::GetDeviceProfileInner;
    funcsMap_[SUBSCRIBE_PROFILE_EVENT] = &DistributedDeviceProfileStub::SubscribeProfileEventInner;
    funcsMap_[UNSUBSCRIBE_PROFILE_EVENT] = &DistributedDeviceProfileStub::UnsubscribeProfileEventInner;
    funcsMap_[SYNC_DEVICE_PROFILE] = &DistributedDeviceProfileStub::SyncDeviceProfileInner;
}

bool DistributedDeviceProfileStub::EnforceInterfaceToken(MessageParcel& data)
{
    return data.ReadInterfaceToken() == IDistributedDeviceProfile::GetDescriptor();
}

int32_t DistributedDeviceProfileStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());

    auto iter = funcsMap_.find(code);
    if (iter != funcsMap_.end()) {
        auto func = iter->second;
        if (!EnforceInterfaceToken(data)) {
            HILOGE("check interface token failed");
            return ERR_DP_INTERFACE_CHECK_FAILED;
        }
        if (!AuthorityManager::GetInstance().CheckCallerTrust()) {
            HILOGE("caller is not trusted");
            return ERR_DP_PERMISSION_DENIED;
        }
        if (func != nullptr) {
            return (this->*func)(data, reply);
        }
    }
    HILOGW("unknown request code, please check");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DistributedDeviceProfileStub::PutDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    ServiceCharacteristicProfile profile;
    if (!profile.Unmarshalling(data)) {
        return ERR_NULL_OBJECT;
    }
    return PutDeviceProfile(profile);
}

int32_t DistributedDeviceProfileStub::GetDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::string udid;
    std::string serviceId;
    ServiceCharacteristicProfile profile;
    PARCEL_READ_HELPER(data, String, udid);
    PARCEL_READ_HELPER(data, String, serviceId);
    int32_t ret = GetDeviceProfile(udid, serviceId, profile);
    if (!(reply.WriteInt32(ret) && profile.Marshalling(reply))) {
        HILOGE("marshall profile failed");
        return ERR_FLATTEN_OBJECT;
    }
    return ERR_NONE;
}

int32_t DistributedDeviceProfileStub::DeleteDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    return DeleteDeviceProfile(data.ReadString());
}

int32_t DistributedDeviceProfileStub::SubscribeProfileEventInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    uint32_t numSubscribeInfos = data.ReadUint32();
    if (numSubscribeInfos == 0 || numSubscribeInfos > MAX_EVENT_LEN) {
        return ERR_DP_INVALID_PARAMS;
    }

    std::list<SubscribeInfo> subscribeInfos;
    for (uint32_t i = 0; i < numSubscribeInfos; i++) {
        SubscribeInfo subscribeInfo;
        if (!subscribeInfo.Unmarshalling(data)) {
            return ERR_NULL_OBJECT;
        }
        HILOGD("profile event = %{public}d", subscribeInfo.profileEvent);
        subscribeInfos.emplace_back(std::move(subscribeInfo));
    }
    sptr<IRemoteObject> eventNotifier = data.ReadRemoteObject();
    std::list<ProfileEvent> failedEvents;

    int32_t errCode = SubscribeProfileEvents(subscribeInfos, eventNotifier, failedEvents);
    HILOGI("errCode = %{public}d", errCode);
    if (!reply.WriteInt32(errCode)) {
        return ERR_FLATTEN_OBJECT;
    }
    if ((errCode != ERR_OK) && !DeviceProfileUtils::WriteProfileEvents(failedEvents, reply)) {
        HILOGE("write profile events failed");
        return ERR_FLATTEN_OBJECT;
    }
    return ERR_NONE;
}

int32_t DistributedDeviceProfileStub::UnsubscribeProfileEventInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    uint32_t numEvents = data.ReadUint32();
    if (numEvents == 0 || numEvents > MAX_EVENT_LEN) {
        return ERR_DP_INVALID_PARAMS;
    }

    std::list<ProfileEvent> profileEvents;
    for (uint32_t i = 0; i < numEvents; i++) {
        ProfileEvent profileEvent = static_cast<ProfileEvent>(data.ReadUint32());
        if (profileEvent >= EVENT_PROFILE_END || profileEvent == EVENT_UNKNOWN) {
            return ERR_DP_INVALID_PARAMS;
        }
        profileEvents.emplace_back(profileEvent);
    }
    sptr<IRemoteObject> eventNotifier = data.ReadRemoteObject();
    std::list<ProfileEvent> failedEvents;

    int32_t errCode = UnsubscribeProfileEvents(profileEvents, eventNotifier, failedEvents);
    HILOGI("errCode = %{public}d", errCode);
    if (!reply.WriteInt32(errCode)) {
        return ERR_FLATTEN_OBJECT;
    }
    if ((errCode != ERR_OK) && !DeviceProfileUtils::WriteProfileEvents(failedEvents, reply)) {
        HILOGE("write profile events failed");
        return ERR_FLATTEN_OBJECT;
    }
    return ERR_NONE;
}

int32_t DistributedDeviceProfileStub::SyncDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    SyncOptions syncOption;
    if (!syncOption.Unmarshalling(data)) {
        HILOGD("unmarshalling failed");
        return ERR_NULL_OBJECT;
    }

    sptr<IRemoteObject> eventNotifier = data.ReadRemoteObject();
    return SyncDeviceProfile(syncOption, eventNotifier);
}
} // namespace DeviceProfile
} // namespace OHOS