/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "profile_change_listener_proxy.h"
#include "macro_utils.h"
#include "distributed_device_profile_errors.h"
#include "dp_ipc_interface_code.h"
#include "i_distributed_device_profile.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ProfileListenerProxy";
}
int32_t ProfileListenerProxy::OnTrustDeviceProfileAdd(const TrustDeviceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnTrustDeviceProfileDelete(const TrustDeviceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_DELETE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnTrustDeviceProfileUpdate(const TrustDeviceProfile& oldProfile,
    const TrustDeviceProfile& newProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!oldProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_UPDATE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnTrustDeviceProfileActive(const TrustDeviceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_ACTIVE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnTrustDeviceProfileInactive(const TrustDeviceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_INACTIVE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnDeviceProfileAdd(const DeviceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_ADD), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnDeviceProfileDelete(const DeviceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_DELETE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnDeviceProfileUpdate(const DeviceProfile& oldProfile, const DeviceProfile& newProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!oldProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_UPDATE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnServiceProfileAdd(const ServiceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_PROFILE_ADD), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnServiceProfileDelete(const ServiceProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_PROFILE_DELETE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnServiceProfileUpdate(const ServiceProfile& oldProfile, const ServiceProfile& newProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!oldProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_PROFILE_UPDATE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnCharacteristicProfileAdd(const CharacteristicProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_CHAR_PROFILE_ADD), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnCharacteristicProfileDelete(const CharacteristicProfile& profile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!profile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_CHAR_PROFILE_DELETE), data, reply);
    return DP_SUCCESS;
}

int32_t ProfileListenerProxy::OnCharacteristicProfileUpdate(const CharacteristicProfile& oldProfile,
    const CharacteristicProfile& newProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_CHANGE_LISTENER_TOKEN(data);
    if (!oldProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newProfile.Marshalling(data)) {
        HILOGE("write reply failed!");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DpIpcInterfaceCode::ON_CHAR_PROFILE_UPDATE), data, reply);
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS

