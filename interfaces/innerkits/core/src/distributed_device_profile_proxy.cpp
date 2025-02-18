/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <memory>
#include "distributed_device_profile_proxy.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DistributedDeviceProfileProxy";
}

int32_t DistributedDeviceProfileProxy::PutAccessControlProfile(const AccessControlProfile& aclProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!aclProfile.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::UpdateAccessControlProfile(const AccessControlProfile& aclProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!aclProfile.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutProductInfoBatch(const std::vector<ProductInfo>& productInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, productInfos)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_PRODUCT_INFO_BATCH), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutDeviceIconInfoBatch(const std::vector<DeviceIconInfo>& deviceIconInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, deviceIconInfos)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_DEVICE_ICON_INFO_BATCH), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetDeviceIconInfos(const DeviceIconInfoFilterOptions& filterOptions,
    std::vector<DeviceIconInfo>& deviceIconInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!filterOptions.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_ICON_INFOS), data, reply);
    if (!IpcUtils::UnMarshalling(reply, deviceIconInfos)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, String, deviceId);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_TRUST_DEVICE_PROFILE), data, reply);
    if (!trustDeviceProfile.UnMarshalling(reply)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE), data, reply);
    if (!IpcUtils::UnMarshalling(reply, trustDeviceProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetAccessControlProfile(std::map<std::string, std::string> queryParams,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, queryParams)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_ACL_PROFILE), data, reply);
    if (!IpcUtils::UnMarshalling(reply, accessControlProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_PROFILE), data, reply);
    if (!IpcUtils::UnMarshalling(reply, accessControlProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::DeleteAccessControlProfile(int32_t accessControlId)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, Int32, accessControlId);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::DELETE_ACL_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, deviceProfiles)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_DEVICE_PROFILE_BATCH), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!serviceProfile.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, serviceProfiles)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutCharacteristicProfile(const CharacteristicProfile& charProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!charProfile.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& charProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, charProfiles)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE_BATCH), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, String, deviceId);
    WRITE_HELPER(data, Bool, deviceProfile.IsMultiUser());
    WRITE_HELPER(data, Int32, deviceProfile.GetUserId());
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILE_NEW), data, reply);
    if (!deviceProfile.UnMarshalling(reply)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetDeviceProfiles(DeviceProfileFilterOptions& options,
    std::vector<DeviceProfile>& deviceProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!options.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILES), data, reply);
    if (!IpcUtils::UnMarshalling(reply, deviceProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::DeleteDeviceProfileBatch(std::vector<DeviceProfile>& deviceProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, deviceProfiles)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::DELETE_DEVICE_PROFILE_BATCH), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, String, deviceId);
    WRITE_HELPER(data, String, serviceName);
    WRITE_HELPER(data, Bool, serviceProfile.IsMultiUser());
    WRITE_HELPER(data, Int32, serviceProfile.GetUserId());
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_PROFILE), data, reply);
    if (!serviceProfile.UnMarshalling(reply)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::PutServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!serviceInfoProfile.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_INFO_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::DeleteServiceInfoProfile(const ServiceInfoUniqueKey& key)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!key.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::DELETE_SERVICE_INFO_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::UpdateServiceInfoProfile(const ServiceInfoProfile& serviceInfoProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!serviceInfoProfile.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::UPDATE_SERVICE_INFO_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileByUniqueKey(const ServiceInfoUniqueKey& key,
    ServiceInfoProfile& serviceInfoProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!key.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_INFO_PROFILE_BY_UNIQUE_KEY), data, reply);
    if (!serviceInfoProfile.UnMarshalling(reply)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileListByTokenId(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!key.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_INFO_PROFILE_LIST_BY_TOKEN_ID),
        data, reply);
    if (!IpcUtils::UnMarshalling(reply, serviceInfoProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetAllServiceInfoProfileList(
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_ALL_SERVICE_INFO_PROFILE_LIST),
        data, reply);
    if (!IpcUtils::UnMarshalling(reply, serviceInfoProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetServiceInfoProfileListByBundleName(const ServiceInfoUniqueKey& key,
    std::vector<ServiceInfoProfile>& serviceInfoProfiles)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!key.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_INFO_PROFILE_LIST_BY_BUNDLE_NAME),
        data, reply);
    if (!IpcUtils::UnMarshalling(reply, serviceInfoProfiles)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, CharacteristicProfile& charProfile)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, String, deviceId);
    WRITE_HELPER(data, String, serviceName);
    WRITE_HELPER(data, String, characteristicId);
    WRITE_HELPER(data, Bool, charProfile.IsMultiUser());
    WRITE_HELPER(data, Int32, charProfile.GetUserId());
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::GET_CHAR_PROFILE), data, reply);
    if (!charProfile.UnMarshalling(reply)) {
        HILOGE("dp ipc read parcel fail");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName, bool isMultiUser, int32_t userId)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, String, deviceId);
    WRITE_HELPER(data, String, serviceName);
    WRITE_HELPER(data, Bool, isMultiUser);
    WRITE_HELPER(data, Int32, userId);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::DEL_SERVICE_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, bool isMultiUser, int32_t userId)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, String, deviceId);
    WRITE_HELPER(data, String, serviceName);
    WRITE_HELPER(data, String, characteristicId);
    WRITE_HELPER(data, Bool, isMultiUser);
    WRITE_HELPER(data, Int32, userId);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::DEL_CHAR_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!subscribeInfo.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!subscribeInfo.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::SyncDeviceProfile(const DpSyncOptions& syncOptions,
    const sptr<IRemoteObject> syncCompletedCallback)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!syncOptions.Marshalling(data)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    WRITE_HELPER(data, RemoteObject, syncCompletedCallback);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::SYNC_DEVICE_PROFILE_NEW), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::SendSubscribeInfos(std::map<std::string, SubscribeInfo> listenerMap)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, listenerMap)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::SEND_SUBSCRIBE_INFOS), data, reply);
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileProxy::SubscribeDeviceProfileInited(int32_t saId, sptr<IRemoteObject> dpInitedCallback)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, Int32, saId);
    WRITE_HELPER(data, RemoteObject, dpInitedCallback);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE_INITED), data, reply);
    return DP_SUCCESS;
}

int32_t OHOS::DistributedDeviceProfile::DistributedDeviceProfileProxy::UnSubscribeDeviceProfileInited(int32_t saId)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    WRITE_HELPER(data, Int32, saId);
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE_INITED), data, reply);
    return DP_SUCCESS;
}

int32_t OHOS::DistributedDeviceProfile::DistributedDeviceProfileProxy::PutAllTrustedDevices(
    const std::vector<TrustedDeviceInfo> deviceInfos)
{
    sptr<IRemoteObject> remote = nullptr;
    GET_REMOTE_OBJECT(remote);
    MessageParcel data;
    WRITE_INTERFACE_TOKEN(data);
    if (!IpcUtils::Marshalling(data, deviceInfos)) {
        HILOGE("dp ipc write parcel fail");
        return DP_WRITE_PARCEL_FAIL;
    }
    MessageParcel reply;
    SEND_REQUEST(remote, static_cast<uint32_t>(DPInterfaceCode::PUT_ALL_TRUSTED_DEVICES), data, reply);
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
