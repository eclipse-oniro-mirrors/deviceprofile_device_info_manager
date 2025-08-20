/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ipc_skeleton.h"
#include "ipc_utils.h"

#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_service_new.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
const std::string TAG = "StubNew";
}

DistributedDeviceProfileStubNew::DistributedDeviceProfileStubNew()
{
    InitAclAndSubscribe();
}

void DistributedDeviceProfileStubNew::InitAclAndSubscribe()
{
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_TRUST_DEVICE_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_ACL_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_INCLUDE_LNN_ACL));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::DELETE_ACL_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::SEND_SUBSCRIBE_INFOS));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE_BATCH));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE_INITED));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE_INITED));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_ALL_TRUSTED_DEVICES));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_DEVICE_PROFILE_BATCH));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILES));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::DELETE_DEVICE_PROFILE_BATCH));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_ICON_INFOS));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_DEVICE_ICON_INFO_BATCH));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_PRODUCT_INFO_BATCH));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::PUT_SESSION_KEY));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::GET_SESSION_KEY));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::UPDATE_SESSION_KEY));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::DELETE_SESSION_KEY));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_PINCODE_INVALID));
    aclAndSubscribeFuncs_.insert(static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_PINCODE_INVALID));
}

DistributedDeviceProfileStubNew::~DistributedDeviceProfileStubNew()
{
    HILOGI("destructor!");
}

bool DistributedDeviceProfileStubNew::IsInterfaceTokenValid(MessageParcel& data)
{
    return data.ReadInterfaceToken() == IDistributedDeviceProfile::GetDescriptor();
}


int32_t DistributedDeviceProfileStubNew::NotifyAclEventInner(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    switch (code) {
        case static_cast<uint32_t>(DPInterfaceCode::PUT_ACL_PROFILE):
            return PutAccessControlProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UPDATE_ACL_PROFILE):
            return UpdateAccessControlProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_TRUST_DEVICE_PROFILE):
            return GetTrustDeviceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_ALL_TRUST_DEVICE_PROFILE):
            return GetAllTrustDeviceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_ACL_PROFILE):
            return GetAccessControlProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_PROFILE):
            return GetAllAccessControlProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_ALL_ACL_INCLUDE_LNN_ACL):
            return GetAllAclIncludeLnnAclInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DELETE_ACL_PROFILE):
            return DeleteAccessControlProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_SESSION_KEY):
            return PutSessionKeyInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_SESSION_KEY):
            return GetSessionKeyInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UPDATE_SESSION_KEY):
            return UpdateSessionKeyInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DELETE_SESSION_KEY):
            return DeleteSessionKeyInner(data, reply);
        default:
            return NotifyProfileDataEventInner(code, data, reply, option);
    }
}

int32_t DistributedDeviceProfileStubNew::NotifyProfileDataEventInner(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE):
            return SubscribeDeviceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE):
            return UnSubscribeDeviceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::SEND_SUBSCRIBE_INFOS):
            return SendSubscribeInfosInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE):
            return PutServiceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_PROFILE_BATCH):
            return PutServiceProfileBatchInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE):
            return PutCharacteristicProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_CHAR_PROFILE_BATCH):
            return PutCharacteristicProfileBatchInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_DEVICE_PROFILE_INITED):
            return SubscribeDeviceProfileInitedInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_DEVICE_PROFILE_INITED):
            return UnSubscribeDeviceProfileInitedInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_ALL_TRUSTED_DEVICES):
            return PutAllTrustedDevicesInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_DEVICE_PROFILE_BATCH):
            return PutDeviceProfileBatchInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILES):
            return GetDeviceProfilesInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_ICON_INFOS):
            return GetDeviceIconInfosInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_DEVICE_ICON_INFO_BATCH):
            return PutDeviceIconInfoBatchInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_PRODUCT_INFO_BATCH):
            return PutProductInfoBatchInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DELETE_DEVICE_PROFILE_BATCH):
            return DeleteDeviceProfileBatchInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::SUBSCRIBE_PINCODE_INVALID):
            return SubscribePinCodeInvalidInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UNSUBSCRIBE_PINCODE_INVALID):
            return UnSubscribePinCodeInvalidInner(data, reply);
        default:
            HILOGE("unknown request code, please check, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t DistributedDeviceProfileStubNew::NotifyEventInner(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    switch (code) {
        case static_cast<uint32_t>(DPInterfaceCode::GET_DEVICE_PROFILE_NEW):
            return GetDeviceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_PROFILE):
            return GetServiceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_CHAR_PROFILE):
            return GetCharacteristicProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DEL_SERVICE_PROFILE):
            return DeleteServiceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DEL_CHAR_PROFILE):
            return DeleteCharacteristicProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::SYNC_DEVICE_PROFILE_NEW):
            return SyncDeviceProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_SERVICE_INFO_PROFILE):
            return PutServiceInfoProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DELETE_SERVICE_INFO_PROFILE):
            return DeleteServiceInfoProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UPDATE_SERVICE_INFO_PROFILE):
            return UpdateServiceInfoProfileInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_INFO_PROFILE_BY_UNIQUE_KEY):
            return GetServiceInfoProfileByUniqueKeyInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_INFO_PROFILE_LIST_BY_TOKEN_ID):
            return GetServiceInfoProfileListByTokenIdInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_ALL_SERVICE_INFO_PROFILE_LIST):
            return GetAllServiceInfoProfileListInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_SERVICE_INFO_PROFILE_LIST_BY_BUNDLE_NAME):
            return GetServiceInfoProfileListByBundleNameInner(data, reply);
        default:
            return NotifyLocalServiceEventInner(code, data, reply, option);
    }
}

int32_t DistributedDeviceProfileStubNew::NotifyLocalServiceEventInner(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    switch (code) {
        case static_cast<uint32_t>(DPInterfaceCode::PUT_LOCAL_SERVICE_INFO):
            return PutLocalServiceInfoInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UPDATE_LOCAL_SERVICE_INFO):
            return UpdateLocalServiceInfoInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_LOCAL_SERVICE_INFO_BY_BINDLE_AND_PINTYPE):
            return GetLocalServiceInfoByBundleAndPinTypeInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::DELETE_LOCAL_SERVICE_INFO):
            return DeleteLocalServiceInfoInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::REGISTER_BUSINESS_CALLBACK):
            return RegisterBusinessCallbackInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::UNREGISTER_BUSINESS_CALLBACK):
            return UnRegisterBusinessCallbackInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::PUT_BUSINESS_EVENT):
            return PutBusinessEventInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::GET_BUSINESS_EVENT):
            return GetBusinessEventInner(data, reply);
        default:
            HILOGW("unknown request code, please check, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t DistributedDeviceProfileStubNew::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u, CallingPid = %{public}u", code, IPCSkeleton::GetCallingPid());
    if (DistributedDeviceProfileServiceNew::GetInstance().IsStopped()) {
        HILOGE("dp service has stopped");
        return DP_SERVICE_STOPPED;
    }
    bool exitIdleStateResult = DistributedDeviceProfileServiceNew::GetInstance().ExitIdleState();
    if (!exitIdleStateResult) {
        HILOGE("CancelIdle failed, ExitIdleState = %{public}d", exitIdleStateResult);
        return DP_SERVICE_ON_IDLE;
    }
    DistributedDeviceProfileServiceNew::GetInstance().AddRunningIpcCount();
    DelayUnloadTask();
    if (!IsInterfaceTokenValid(data)) {
        HILOGE("check interface token failed");
        DistributedDeviceProfileServiceNew::GetInstance().SubtractRunningIpcCount();
        return DP_INTERFACE_CHECK_FAILED;
    }
    if (aclAndSubscribeFuncs_.find(code) != aclAndSubscribeFuncs_.end()) {
        int32_t aclRet = NotifyAclEventInner(code, data, reply, option);
        DistributedDeviceProfileServiceNew::GetInstance().SubtractRunningIpcCount();
        return aclRet;
    }
    if (!IsInited()) {
        HILOGE("DP not finish init");
        DistributedDeviceProfileServiceNew::GetInstance().SubtractRunningIpcCount();
        return DP_LOAD_SERVICE_ERR;
    }
    int32_t ret = NotifyEventInner(code, data, reply, option);
    DistributedDeviceProfileServiceNew::GetInstance().SubtractRunningIpcCount();
    return ret;
}

int32_t DistributedDeviceProfileStubNew::PutAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
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
    HILOGD("called");
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
    HILOGD("called");
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
    HILOGD("called");
    std::vector<TrustDeviceProfile> trustDeviceProfiles;
    int32_t ret = GetAllTrustDeviceProfile(trustDeviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, trustDeviceProfiles)) {
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    std::map<std::string, std::string> queryParams;
    if (!IpcUtils::UnMarshalling(data, queryParams)) {
        return DP_READ_PARCEL_FAIL;
    }
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = GetAccessControlProfile(queryParams, accessControlProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, accessControlProfiles)) {
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAllAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = GetAllAccessControlProfile(accessControlProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, accessControlProfiles)) {
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAllAclIncludeLnnAclInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    std::vector<AccessControlProfile> accessControlProfiles;
    int32_t ret = GetAllAclIncludeLnnAcl(accessControlProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, accessControlProfiles)) {
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteAccessControlProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    int32_t accessControlId;
    READ_HELPER(data, Int32, accessControlId);
    int32_t ret = DeleteAccessControlProfile(accessControlId);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutSessionKeyInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    int32_t sessionKeyId = 0;
    READ_HELPER(data, Uint32, userId);
    if (!IpcUtils::UnMarshalling(data, sessionKey)) {
        sessionKey.clear();
        return DP_WRITE_PARCEL_FAIL;
    }
    int32_t ret = PutSessionKey(userId, sessionKey, sessionKeyId);
    if (!reply.WriteInt32(ret)) {
        sessionKey.clear();
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    WRITE_HELPER(reply, Int32, sessionKeyId);
    sessionKey.clear();
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetSessionKeyInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    uint32_t userId = 0;
    int32_t sessionKeyId = 0;
    std::vector<uint8_t> sessionKey;
    READ_HELPER(data, Uint32, userId);
    READ_HELPER(data, Int32, sessionKeyId);
    int32_t ret = GetSessionKey(userId, sessionKeyId, sessionKey);
    if (!reply.WriteInt32(ret)) {
        sessionKey.clear();
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    if (!IpcUtils::Marshalling(reply, sessionKey)) {
        sessionKey.clear();
        return DP_WRITE_PARCEL_FAIL;
    }
    sessionKey.clear();
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UpdateSessionKeyInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    uint32_t userId = 0;
    std::vector<uint8_t> sessionKey;
    int32_t sessionKeyId = 0;
    READ_HELPER(data, Uint32, userId);
    READ_HELPER(data, Int32, sessionKeyId);
    if (!IpcUtils::UnMarshalling(data, sessionKey)) {
        sessionKey.clear();
        return DP_WRITE_PARCEL_FAIL;
    }
    int32_t ret = UpdateSessionKey(userId, sessionKeyId, sessionKey);
    if (!reply.WriteInt32(ret)) {
        sessionKey.clear();
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    sessionKey.clear();
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteSessionKeyInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    uint32_t userId = 0;
    int32_t sessionKeyId = 0;
    READ_HELPER(data, Uint32, userId);
    READ_HELPER(data, Int32, sessionKeyId);
    int32_t ret = DeleteSessionKey(userId, sessionKeyId);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutServiceProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
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
    bool isMultiUser = false;
    int32_t userId = DEFAULT_USER_ID;
    DeviceProfile deviceProfile;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, Bool, isMultiUser);
    READ_HELPER(data, Int32, userId);
    deviceProfile.SetIsMultiUser(isMultiUser);
    deviceProfile.SetUserId(userId);
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
    bool isMultiUser = false;
    int32_t userId = DEFAULT_USER_ID;
    ServiceProfile serviceProfile;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, Bool, isMultiUser);
    READ_HELPER(data, Int32, userId);
    serviceProfile.SetIsMultiUser(isMultiUser);
    serviceProfile.SetUserId(userId);
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
    bool isMultiUser = false;
    int32_t userId = DEFAULT_USER_ID;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, String, characteristicKey);
    READ_HELPER(data, Bool, isMultiUser);
    READ_HELPER(data, Int32, userId);
    CharacteristicProfile charProfile;
    charProfile.SetIsMultiUser(isMultiUser);
    charProfile.SetUserId(userId);
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
    bool isMultiUser = false;
    int32_t userId = DEFAULT_USER_ID;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, Bool, isMultiUser);
    READ_HELPER(data, Int32, userId);
    int32_t ret = DeleteServiceProfile(deviceId, serviceName, isMultiUser, userId);
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
    bool isMultiUser = false;
    int32_t userId = DEFAULT_USER_ID;
    READ_HELPER(data, String, deviceId);
    READ_HELPER(data, String, serviceName);
    READ_HELPER(data, String, characteristicKey);
    READ_HELPER(data, Bool, isMultiUser);
    READ_HELPER(data, Int32, userId);
    int32_t ret = DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey, isMultiUser, userId);
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
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = SendSubscribeInfos(listenerMap);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::SubscribeDeviceProfileInitedInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t saId = -1;
    READ_HELPER(data, Int32, saId);
    sptr<IRemoteObject> dpInitedCallback = data.ReadRemoteObject();
    if (dpInitedCallback == nullptr) {
        HILOGE("read remoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t ret = SubscribeDeviceProfileInited(saId, dpInitedCallback);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UnSubscribeDeviceProfileInitedInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t saId = -1;
    READ_HELPER(data, Int32, saId);
    int32_t ret = UnSubscribeDeviceProfileInited(saId);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutAllTrustedDevicesInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<TrustedDeviceInfo> deviceInfos;
    if (!IpcUtils::UnMarshalling(data, deviceInfos)) {
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutAllTrustedDevices(deviceInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutLocalServiceInfoInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    LocalServiceInfo localServiceInfo;
    if (!localServiceInfo.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutLocalServiceInfo(localServiceInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UpdateLocalServiceInfoInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    LocalServiceInfo localServiceInfo;
    if (!localServiceInfo.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = UpdateLocalServiceInfo(localServiceInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetLocalServiceInfoByBundleAndPinTypeInner(MessageParcel& data,
    MessageParcel& reply)
{
    LocalServiceInfo localServiceInfo;
    int32_t pinExchangeType = 0;
    std::string bundleName = "";
    READ_HELPER(data, String, bundleName);
    READ_HELPER(data, Int32, pinExchangeType);
    int32_t ret = GetLocalServiceInfoByBundleAndPinType(bundleName, pinExchangeType, localServiceInfo);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!localServiceInfo.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteLocalServiceInfoInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t pinExchangeType = 0;
    std::string bundleName = "";
    READ_HELPER(data, String, bundleName);
    READ_HELPER(data, Int32, pinExchangeType);
    int32_t ret = DeleteLocalServiceInfo(bundleName, pinExchangeType);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutDeviceProfileBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<DeviceProfile> deviceProfiles;
    if (!IpcUtils::UnMarshalling(data, deviceProfiles)) {
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutDeviceProfileBatch(deviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetDeviceProfilesInner(MessageParcel& data, MessageParcel& reply)
{
    DeviceProfileFilterOptions options;
    std::vector<DeviceProfile> deviceProfiles;
    if (!options.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = GetDeviceProfiles(options, deviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, deviceProfiles)) {
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::SubscribePinCodeInvalidInner(MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = "";
    int32_t pinExchangeType = DEFAULT_PIN_EXCHANGE_TYPE;
    READ_HELPER(data, String, bundleName);
    READ_HELPER(data, Int32, pinExchangeType);
    sptr<IRemoteObject> pincodeInvalidCallback = data.ReadRemoteObject();
    if (pincodeInvalidCallback == nullptr) {
        HILOGE("read remoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t ret = SubscribePinCodeInvalid(bundleName,
        pinExchangeType, pincodeInvalidCallback);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UnSubscribePinCodeInvalidInner(MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = "";
    int32_t pinExchangeType = DEFAULT_PIN_EXCHANGE_TYPE;
    READ_HELPER(data, String, bundleName);
    READ_HELPER(data, Int32, pinExchangeType);
    int32_t ret = UnSubscribePinCodeInvalid(bundleName,
        pinExchangeType);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutProductInfoBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<ProductInfo> productInfos;
    if (!IpcUtils::UnMarshalling(data, productInfos)) {
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutProductInfoBatch(productInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutDeviceIconInfoBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<DeviceIconInfo> deviceIconInfos;
    if (!IpcUtils::UnMarshalling(data, deviceIconInfos)) {
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutDeviceIconInfoBatch(deviceIconInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetDeviceIconInfosInner(MessageParcel& data, MessageParcel& reply)
{
    DeviceIconInfoFilterOptions filterOptions;
    std::vector<DeviceIconInfo> deviceIconInfos;
    if (!filterOptions.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = GetDeviceIconInfos(filterOptions,
        deviceIconInfos);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!IpcUtils::Marshalling(reply, deviceIconInfos)) {
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutServiceInfoProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    ServiceInfoProfile serviceInfoProfile;
    if (!serviceInfoProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutServiceInfoProfile(serviceInfoProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteServiceInfoProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    ServiceInfoUniqueKey key;
    if (!key.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DeleteServiceInfoProfile(key);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UpdateServiceInfoProfileInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    ServiceInfoProfile serviceInfoProfile;
    if (!serviceInfoProfile.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = UpdateServiceInfoProfile(serviceInfoProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetServiceInfoProfileByUniqueKeyInner(MessageParcel& data,
    MessageParcel& reply)
{
    ServiceInfoUniqueKey key;
    ServiceInfoProfile serviceInfoProfile;
    if (!key.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = GetServiceInfoProfileByUniqueKey(key,
        serviceInfoProfile);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!serviceInfoProfile.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetServiceInfoProfileListByTokenIdInner(MessageParcel& data,
    MessageParcel& reply)
{
    ServiceInfoUniqueKey key;
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    if (!key.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = GetServiceInfoProfileListByTokenId(key,
        serviceInfoProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
 
    if (!IpcUtils::Marshalling(reply, serviceInfoProfiles)) {
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetAllServiceInfoProfileListInner(MessageParcel& data,
    MessageParcel& reply)
{
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    int32_t ret = GetAllServiceInfoProfileList(serviceInfoProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
 
    if (!IpcUtils::Marshalling(reply, serviceInfoProfiles)) {
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetServiceInfoProfileListByBundleNameInner(MessageParcel& data,
    MessageParcel& reply)
{
    ServiceInfoUniqueKey key;
    std::vector<ServiceInfoProfile> serviceInfoProfiles;
    if (!key.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = GetServiceInfoProfileListByBundleName(key,
        serviceInfoProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
 
    if (!IpcUtils::Marshalling(reply, serviceInfoProfiles)) {
        return DP_READ_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::DeleteDeviceProfileBatchInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<DeviceProfile> deviceProfiles;
    if (!IpcUtils::UnMarshalling(data, deviceProfiles)) {
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = DeleteDeviceProfileBatch(deviceProfiles);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::RegisterBusinessCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    std::string saId = "";
    std::string businessKey = "";
    READ_HELPER(data, String, saId);
    READ_HELPER(data, String, businessKey);
    sptr<IRemoteObject> businessCallback = data.ReadRemoteObject();
    if (businessCallback == nullptr) {
        HILOGE("read remoteObject failed!");
        return ERR_FLATTEN_OBJECT;
    }
    int32_t ret = RegisterBusinessCallback(saId, businessKey, businessCallback);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::UnRegisterBusinessCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    std::string saId = "";
    std::string businessKey = "";
    READ_HELPER(data, String, saId);
    READ_HELPER(data, String, businessKey);
    int32_t ret = UnRegisterBusinessCallback(saId, businessKey);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::PutBusinessEventInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    BusinessEvent event;
    if (!event.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = PutBusinessEvent(event);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}

int32_t DistributedDeviceProfileStubNew::GetBusinessEventInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGD("called");
    BusinessEvent event;
    if (!event.UnMarshalling(data)) {
        HILOGE("read parcel fail!");
        return DP_READ_PARCEL_FAIL;
    }
    int32_t ret = GetBusinessEvent(event);
    if (!reply.WriteInt32(ret)) {
        HILOGE("Write reply failed");
        return DP_WRITE_PARCEL_FAIL;
    }
    if (!event.Marshalling(reply)) {
        HILOGE("write parcel fail!");
        return DP_WRITE_PARCEL_FAIL;
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
