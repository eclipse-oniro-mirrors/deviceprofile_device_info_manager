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

#include "distributed_device_profile_proxy.h"

#include "device_profile_log.h"
#include "device_profile_utils.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileProxy";
}

int32_t DistributedDeviceProfileProxy::PutDeviceProfile(const ServiceCharacteristicProfile& profile)
{
    sptr<IRemoteObject> remote = Remote();
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDistributedDeviceProfile::GetDescriptor())) {
        HILOGE("write interface token failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!profile.Marshalling(data)) {
        HILOGE("marshall profile failed");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, PUT_DEVICE_PROFILE, data, reply);
}

int32_t DistributedDeviceProfileProxy::GetDeviceProfile(const std::string& udid, const std::string& serviceId,
    ServiceCharacteristicProfile& profile)
{
    sptr<IRemoteObject> remote = Remote();
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDistributedDeviceProfile::GetDescriptor())) {
        HILOGE("write interface token failed");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, udid);
    PARCEL_WRITE_HELPER(data, String, serviceId);
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(GET_DEVICE_PROFILE, data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("transact failed, error: %{public}d", error);
        return error;
    }
    profile.Unmarshalling(reply);
    return ERR_OK;
}

int32_t DistributedDeviceProfileProxy::DeleteDeviceProfile(const std::string& serviceId)
{
    sptr<IRemoteObject> remote = Remote();
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDistributedDeviceProfile::GetDescriptor())) {
        HILOGE("write inteface token failed");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, serviceId);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, DELETE_DEVICE_PROFILE, data, reply);
}

int32_t DistributedDeviceProfileProxy::SubscribeProfileEvents(
    const std::list<SubscribeInfo>& subscribeInfos,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    sptr<IRemoteObject> remote = Remote();
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDistributedDeviceProfile::GetDescriptor())) {
        HILOGE("write inteface token failed");
        return ERR_FLATTEN_OBJECT;
    }
    size_t size = subscribeInfos.size();
    PARCEL_WRITE_HELPER(data, Uint32, static_cast<uint32_t>(size));
    for (const auto& subscribeInfo : subscribeInfos) {
        if (!subscribeInfo.Marshalling(data)) {
            HILOGE("marshall subscribe info failed");
            return ERR_FLATTEN_OBJECT;
        }
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, profileEventNotifier);
    MessageParcel reply;
    MessageOption option;
    int32_t errCode = remote->SendRequest(SUBSCRIBE_PROFILE_EVENT, data, reply, option);
    if (errCode != ERR_OK) {
        HILOGE("transact failed, errCode = %{public}d", errCode);
        if (!DeviceProfileUtils::ReadProfileEvents(reply, failedEvents)) {
            HILOGW("read profile events failed");
        }
    }
    return errCode;
}

int32_t DistributedDeviceProfileProxy::UnsubscribeProfileEvents(
    const std::list<ProfileEvent>& profileEvents,
    const sptr<IRemoteObject>& profileEventNotifier,
    std::list<ProfileEvent>& failedEvents)
{
    sptr<IRemoteObject> remote = Remote();
    MessageParcel data;
    if (!data.WriteInterfaceToken(IDistributedDeviceProfile::GetDescriptor())) {
        HILOGE("write inteface token failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!DeviceProfileUtils::WriteProfileEvents(profileEvents, data)) {
        return ERR_FLATTEN_OBJECT;
    }

    PARCEL_WRITE_HELPER(data, RemoteObject, profileEventNotifier);
    MessageParcel reply;
    MessageOption option;
    int32_t errCode = remote->SendRequest(UNSUBSCRIBE_PROFILE_EVENT, data, reply, option);
    if (errCode != ERR_OK) {
        HILOGE("transact failed, errCode = %{public}d", errCode);
        if (!DeviceProfileUtils::ReadProfileEvents(reply, failedEvents)) {
            HILOGW("read profile events failed");
        }
    }
    return errCode;
}
} // namespace DeviceProfile
} // namespace OHOS