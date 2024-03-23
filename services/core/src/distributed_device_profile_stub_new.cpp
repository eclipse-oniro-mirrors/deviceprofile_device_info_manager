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

#include "distributed_device_profile_stub_new.h"

#include <string>
#include "ipc_utils.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_enums.h"
#include "profile_utils.h"
#include "macro_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "DistributedDeviceProfileStubNew";
}

DistributedDeviceProfileStubNew::DistributedDeviceProfileStubNew()
{
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE)] =
        &DistributedDeviceProfileStubNew::PutAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE)] =
        &DistributedDeviceProfileStubNew::UpdateAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_TRUST_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::GetTrustDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::GetAllTrustDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_ACL_PROFILE)] =
        &DistributedDeviceProfileStubNew::GetAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_PROFILE)] =
            &DistributedDeviceProfileStubNew::GetAllAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::DELETE_ACL_PROFILE)] =
        &DistributedDeviceProfileStubNew::DeleteAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::PutServiceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH)] =
        &DistributedDeviceProfileStubNew::PutServiceProfileBatchInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE)] =
        &DistributedDeviceProfileStubNew::PutCharacteristicProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE_BATCH)] =
        &DistributedDeviceProfileStubNew::PutCharacteristicProfileBatchInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILE_NEW)] =
        &DistributedDeviceProfileStubNew::GetDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::GetServiceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_CHAR_PROFILE)] =
        &DistributedDeviceProfileStubNew::GetCharacteristicProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::DEL_SERVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::DeleteServiceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::DEL_CHAR_PROFILE)] =
        &DistributedDeviceProfileStubNew::DeleteCharacteristicProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::SubscribeDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStubNew::UnSubscribeDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::SYNC_DEVICE_PROFILE_NEW)] =
        &DistributedDeviceProfileStubNew::SyncDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::SEND_SUBSCRIBE_INFOS)] =
            &DistributedDeviceProfileStubNew::SendSubscribeInfosInner;
}

DistributedDeviceProfileStubNew::~DistributedDeviceProfileStubNew()
{
    HILOGI("destructor!");
}

bool DistributedDeviceProfileStubNew::IsInterfaceTokenValid(MessageParcel& data)
{
    return data.ReadInterfaceToken() == IDistributedDeviceProfile::GetDescriptor();
}

int32_t DistributedDeviceProfileStubNew::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    auto iter = funcsMap_.find(code);
    if (iter == funcsMap_.end()) {
        HILOGW("unknown request code, please check");
        return DP_INVALID_PARAMS;
    }
    if (!IsInterfaceTokenValid(data)) {
        HILOGE("check interface token failed");
        return DP_INTERFACE_CHECK_FAILED;
    }
    auto func = iter->second;
    if (func != nullptr) {
        return (this->*func)(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t DistributedDeviceProfileStubNew::PutAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    AccessControlProfile accessControlProfile;
    if (!accessControlProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutAccessControlProfile(accessControlProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UpdateAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    AccessControlProfile accessControlProfile;
    if (!accessControlProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = UpdateAccessControlProfile(accessControlProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetTrustDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::string deviceId;
    READ_HELPER(data, String, deviceId);
    TrustDeviceProfile trustDeviceProfile;
    int32_t ret = GetTrustDeviceProfile(deviceId, trustDeviceProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!trustDeviceProfile.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAllTrustDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    int32_t ret = GetAllTrustDeviceProfile(trustDeviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, trustDeviceProfiles)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::map<std::string, std::string> queryParams;
    if (!IpcUtils::UnMarshalling(data, queryParams)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = GetAccessControlProfile(queryParams, accessControlProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, accessControlProfiles)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAllAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = GetAllAccessControlProfile(accessControlProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, accessControlProfiles)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    int32_t accessControlId;
    READ_HELPER(data, Int32, accessControlId);
    int32_t ret = DeleteAccessControlProfile(accessControlId);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    ServiceProfile serviceProfile;
    if (!serviceProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutServiceProfile(serviceProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutServiceProfileBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<ServiceProfile> serviceProfiles;
    if (!IpcUtils::UnMarshalling(data, serviceProfiles)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutServiceProfileBatch(serviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply)
{
    CharacteristicProfile charProfile;
    if (!charProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutCharacteristicProfile(charProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutCharacteristicProfileBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<CharacteristicProfile> charProfiles;
    if (!IpcUtils::UnMarshalling(data, charProfiles)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutCharacteristicProfileBatch(charProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    DeviceProfile deviceProfile;
    READ_HELPER(data, String, deviceId);
    int32_t ret = GetDeviceProfile(deviceId, deviceProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!deviceProfile.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    ServiceProfile serviceProfile;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    int32_t ret = GetServiceProfile(deviceId, serviceName, serviceProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!serviceProfile.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    std::string characteristicKey;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, String, characteristicKey);
    CharacteristicProfile charProfile;
    int32_t ret = GetCharacteristicProfile(deviceId, serviceName, characteristicKey, charProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!charProfile.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    int32_t ret = DeleteServiceProfile(deviceId, serviceName);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    std::string characteristicKey;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, String, characteristicKey);
    int32_t ret = DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::SubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    SubscribeInfo subscribeInfo;
    if (!subscribeInfo.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = SubscribeDeviceProfile(subscribeInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UnSubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    SubscribeInfo subscribeInfo;
    if (!subscribeInfo.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = UnSubscribeDeviceProfile(subscribeInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::SyncDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    DistributedDeviceProfile::DpSyncOptions syncOptions;
    if (!syncOptions.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    sptr<IRemoteObject> syncCompletedCallback = data.ReadRemoteObject();
    int32_t ret = SyncDeviceProfile(syncOptions, syncCompletedCallback);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}


int32_t DistributedDeviceProfileStubNew::SendSubscribeInfosInner(MessageParcel& data, MessageParcel& reply)
{
    std::map<std::string, SubscribeInfo> listenerMap;
    if (!IpcUtils::UnMarshalling(data, listenerMap)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = SendSubscribeInfos(listenerMap);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
