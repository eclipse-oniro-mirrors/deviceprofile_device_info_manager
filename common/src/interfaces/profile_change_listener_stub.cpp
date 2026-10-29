/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "profile_change_listener_stub.h"

#include "message_parcel.h"

#include "access_control_profile.h"
#include "characteristic_profile.h"
#include "device_profile.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_ipc_interface_code.h"
#include "ipc_utils.h"
#include "service_profile.h"
#include "trust_device_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    constexpr char TAG[] = "ProfileChangeListenerStub";
}
ProfileChangeListenerStub::ProfileChangeListenerStub()
{
    HILOGI("construct!");
}

ProfileChangeListenerStub::~ProfileChangeListenerStub()
{
    HILOGI("destruct!");
}

bool ProfileChangeListenerStub::IsInterfaceToken(MessageParcel& data)
{
    return data.ReadInterfaceToken() == IProfileChangeListener::GetDescriptor();
}

int32_t ProfileChangeListenerStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u, flags = %{public}d", code, option.GetFlags());

    if (!IsInterfaceToken(data)) {
        HILOGE("check interface token failed");
        return DP_INTERFACE_CHECK_FAILED;
    }
    switch (code) {
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD):
            return OnTrustDeviceProfileAddInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_DELETE):
            return OnTrustDeviceProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_UPDATE):
            return OnTrustDeviceProfileUpdateInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_ACTIVE):
            return OnTrustDeviceProfileActiveInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_TRUST_DEVICE_PROFILE_INACTIVE):
            return OnTrustDeviceProfileInactiveInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_ACL_INACTIVE_BY_DELETE):
            return OnDeviceAclInactiveByDeleteInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_ACL_INACTIVE_BY_UPDATE):
            return OnDeviceAclInactiveByUpdateInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_ACCOUNT_ACL_DELETE):
            return OnAccountAclDeleteInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_ACCOUNT_ACL_INACTIVE):
            return OnAccountAclInactiveInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_ACCOUNT_ACL_ADD):
            return OnAccountAclAddInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_ACCOUNT_ACL_ACTIVE):
            return OnAccountAclActiveInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_ADD):
            return OnDeviceProfileAddInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_DELETE):
            return OnDeviceProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_DEVICE_PROFILE_UPDATE):
            return OnDeviceProfileUpdateInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_PROFILE_ADD):
            return OnServiceProfileAddInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_PROFILE_DELETE):
            return OnServiceProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_SERVICE_PROFILE_UPDATE):
            return OnServiceProfileUpdateInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_CHAR_PROFILE_ADD):
            return OnCharacteristicProfileAddInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_CHAR_PROFILE_DELETE):
            return OnCharacteristicProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DpIpcInterfaceCode::ON_CHAR_PROFILE_UPDATE):
            return OnCharacteristicProfileUpdateInner(data, reply);
        default:
            break;
    }
    HILOGW("unknown request code, please check, code = %{public}u", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileAddInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnTrustDeviceProfileAdd(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnTrustDeviceProfileDelete(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile oldTrustDeviceProfile;
    TrustDeviceProfile newTrustDeviceProfile;
    if (!oldTrustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newTrustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnTrustDeviceProfileUpdate(oldTrustDeviceProfile, newTrustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileActiveInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnTrustDeviceProfileActive(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileInactiveInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnTrustDeviceProfileInactive(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceAclInactiveByDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnDeviceAclInactiveByDelete(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceAclInactiveByUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnDeviceAclInactiveByUpdate(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnAccountAclDelete(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclInactiveInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnAccountAclInactive(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclAddInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnAccountAclAdd(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclActiveInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    TrustDeviceProfile trustDeviceProfile;
    if (!trustDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnAccountAclActive(trustDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceProfileAddInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    DeviceProfile deviceProfile;
    if (!deviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnDeviceProfileAdd(deviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceProfileDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    DeviceProfile deviceProfile;
    if (!deviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnDeviceProfileDelete(deviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceProfileUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    DeviceProfile oldDeviceProfile;
    DeviceProfile newDeviceProfile;
    if (!oldDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newDeviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnDeviceProfileUpdate(oldDeviceProfile, newDeviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnServiceProfileAddInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    ServiceProfile serviceProfile;
    if (!serviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnServiceProfileAdd(serviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnServiceProfileDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    ServiceProfile serviceProfile;
    if (!serviceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnServiceProfileDelete(serviceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnServiceProfileUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    ServiceProfile oldServiceProfile;
    ServiceProfile newServiceProfile;
    if (!oldServiceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newServiceProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnServiceProfileUpdate(oldServiceProfile, newServiceProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnCharacteristicProfileAddInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    CharacteristicProfile characteristicProfile;
    if (!characteristicProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnCharacteristicProfileAdd(characteristicProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnCharacteristicProfileDeleteInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    CharacteristicProfile characteristicProfile;
    if (!characteristicProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnCharacteristicProfileDelete(characteristicProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnCharacteristicProfileUpdateInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called");
    CharacteristicProfile oldCharacteristicProfile;
    CharacteristicProfile newCharacteristicProfile;
    if (!oldCharacteristicProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    if (!newCharacteristicProfile.UnMarshalling(data)) {
        HILOGE("Read reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    OnCharacteristicProfileUpdate(oldCharacteristicProfile, newCharacteristicProfile);
    if (!reply.WriteInt32(DP_SUCCESS)) {
        HILOGE("Write reply failed");
        return ERR_FLATTEN_OBJECT;
    }
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileActive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnTrustDeviceProfileInactive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceAclInactiveByDelete(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnDeviceAclInactiveByUpdate(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclDelete(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclInactive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclAdd(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}

int32_t ProfileChangeListenerStub::OnAccountAclActive(const TrustDeviceProfile& profile)
{
    (void)profile;
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
