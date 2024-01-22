/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "deviceprofile_ipc_interface_code.h"
#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage.h"
#include "device_profile_utils.h"
#include "iprofile_event_notifier.h"
#include "parcel_helper.h"
#include "distributed_device_profile_service_new.h"
#include "distributed_device_profile_errors.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::DistributedDeviceProfile;
namespace {
const std::string TAG = "DistributedDeviceProfileStub";
constexpr uint32_t MAX_EVENT_LEN = 1000000;
}

DistributedDeviceProfileStub::DistributedDeviceProfileStub()
{
    funcsMap_[static_cast<uint32_t>(IDeviceProfileInterfaceCode::PUT_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::PutDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(IDeviceProfileInterfaceCode::DELETE_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::DeleteDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(IDeviceProfileInterfaceCode::GET_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::GetDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(IDeviceProfileInterfaceCode::SUBSCRIBE_PROFILE_EVENT)] =
        &DistributedDeviceProfileStub::SubscribeProfileEventInner;
    funcsMap_[static_cast<uint32_t>(IDeviceProfileInterfaceCode::UNSUBSCRIBE_PROFILE_EVENT)] =
        &DistributedDeviceProfileStub::UnsubscribeProfileEventInner;
    funcsMap_[static_cast<uint32_t>(IDeviceProfileInterfaceCode::SYNC_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::SyncDeviceProfileInner;
    InitNewIpcInterface();
}

void DistributedDeviceProfileStub::InitNewIpcInterface()
{
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE)] =
        &DistributedDeviceProfileStub::PutAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE)] =
        &DistributedDeviceProfileStub::UpdateAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_TRUST_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::GetTrustDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::GetAllTrustDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_ACL_PROFILE)] =
        &DistributedDeviceProfileStub::GetAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_PROFILE)] =
        &DistributedDeviceProfileStub::GetAllAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::DELETE_ACL_PROFILE)] =
        &DistributedDeviceProfileStub::DeleteAccessControlProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE)] =
        &DistributedDeviceProfileStub::PutServiceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH)] =
        &DistributedDeviceProfileStub::PutServiceProfileBatchInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE)] =
        &DistributedDeviceProfileStub::PutCharacteristicProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE_BATCH)] =
        &DistributedDeviceProfileStub::PutCharacteristicProfileBatchInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILE_NEW)] =
        &DistributedDeviceProfileStub::GetDeviceProfileNewInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_PROFILE)] =
        &DistributedDeviceProfileStub::GetServiceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::GET_CHAR_PROFILE)] =
        &DistributedDeviceProfileStub::GetCharacteristicProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::DEL_SERVICE_PROFILE)] =
        &DistributedDeviceProfileStub::DeleteServiceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::DEL_CHAR_PROFILE)] =
        &DistributedDeviceProfileStub::DeleteCharacteristicProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::SubscribeDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE)] =
        &DistributedDeviceProfileStub::UnSubscribeDeviceProfileInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::SYNC_DEVICE_PROFILE_NEW)] =
        &DistributedDeviceProfileStub::SyncDeviceProfileNewInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::SEND_SUBSCRIBE_INFOS)] =
        &DistributedDeviceProfileStub::SendSubscribeInfosInner;
}

bool DistributedDeviceProfileStub::EnforceInterfaceToken(MessageParcel& data)
{
    return data.ReadInterfaceToken() == IDistributedDeviceProfile::GetDescriptor();
}

int32_t DistributedDeviceProfileStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());
    DelayUnloadTask();
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
        HILOGD("profile event = %{public}u", static_cast<uint32_t>(subscribeInfo.profileEvent));
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

int32_t DistributedDeviceProfileStub::PutAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    AccessControlProfile accessControlProfile;
    if (!accessControlProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutAccessControlProfile(accessControlProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::UpdateAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    AccessControlProfile accessControlProfile;
    if (!accessControlProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UpdateAccessControlProfile(accessControlProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::GetTrustDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::string deviceId;
    READ_HELPER(data, String, deviceId);
    TrustDeviceProfile trustDeviceProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetTrustDeviceProfile(deviceId, trustDeviceProfile);
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

int32_t DistributedDeviceProfileStub::GetAllTrustDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetAllTrustDeviceProfile(trustDeviceProfiles);
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

int32_t DistributedDeviceProfileStub::GetAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::map<std::string, std::string> queryParams;
    if (!IpcUtils::UnMarshalling(data, queryParams)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret =
        DistributedDeviceProfileServiceNew::GetInstance().GetAccessControlProfile(queryParams, accessControlProfiles);
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

int32_t DistributedDeviceProfileStub::GetAllAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetAllAccessControlProfile(accessControlProfiles);
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

int32_t DistributedDeviceProfileStub::DeleteAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    int32_t accessControlId;
    READ_HELPER(data, Int32, accessControlId);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteAccessControlProfile(accessControlId);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::PutServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    ServiceProfile serviceProfile;
    if (!serviceProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceProfile(serviceProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::PutServiceProfileBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<ServiceProfile> serviceProfiles;
    if (!IpcUtils::UnMarshalling(data, serviceProfiles)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutServiceProfileBatch(serviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::PutCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply)
{
    CharacteristicProfile charProfile;
    if (!charProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutCharacteristicProfile(charProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::PutCharacteristicProfileBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<CharacteristicProfile> charProfiles;
    if (!IpcUtils::UnMarshalling(data, charProfiles)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().PutCharacteristicProfileBatch(charProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::GetDeviceProfileNewInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    OHOS::DistributedDeviceProfile::DeviceProfile deviceProfile;
    READ_HELPER(data, String, deviceId);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetDeviceProfile(deviceId, deviceProfile);
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

int32_t DistributedDeviceProfileStub::GetServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    ServiceProfile serviceProfile;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    int32_t ret =
        DistributedDeviceProfileServiceNew::GetInstance().GetServiceProfile(deviceId, serviceName, serviceProfile);
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

int32_t DistributedDeviceProfileStub::GetCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    std::string characteristicKey;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, String, characteristicKey);
    CharacteristicProfile charProfile;
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().GetCharacteristicProfile(deviceId, serviceName,
        characteristicKey, charProfile);
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

int32_t DistributedDeviceProfileStub::DeleteServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteServiceProfile(deviceId, serviceName);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::DeleteCharacteristicProfileInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceId;
    std::string serviceName;
    std::string characteristicKey;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, String, characteristicKey);
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().DeleteCharacteristicProfile(deviceId, serviceName,
        characteristicKey);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::SubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    OHOS::DistributedDeviceProfile::SubscribeInfo subscribeInfo;
    if (!subscribeInfo.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().SubscribeDeviceProfile(subscribeInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::UnSubscribeDeviceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    OHOS::DistributedDeviceProfile::SubscribeInfo subscribeInfo;
    subscribeInfo.UnMarshalling(data);
    if (!subscribeInfo.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().UnSubscribeDeviceProfile(subscribeInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStub::SyncDeviceProfileNewInner(MessageParcel& data, MessageParcel& reply)
{
    OHOS::DistributedDeviceProfile::SyncOptions syncOptions;
    if (!syncOptions.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    sptr<IRemoteObject> syncCompletedCallback = data.ReadRemoteObject();
    int32_t ret =
        DistributedDeviceProfileServiceNew::GetInstance().SyncDeviceProfile(syncOptions, syncCompletedCallback);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}


int32_t DistributedDeviceProfileStub::SendSubscribeInfosInner(MessageParcel& data, MessageParcel& reply)
{
    std::map<std::string, OHOS::DistributedDeviceProfile::SubscribeInfo> listenerMap;
    if (!IpcUtils::UnMarshalling(data, listenerMap)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DistributedDeviceProfileServiceNew::GetInstance().SendSubscribeInfos(listenerMap);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
