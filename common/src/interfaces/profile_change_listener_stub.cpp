/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "distributed_device_profile_errors.h"
#include "trust_device_profile.h"
#include "access_control_profile.h"
#include "device_profile.h"
#include "service_profile.h"
#include "characteristic_profile.h"
#include "distributed_device_profile_log.h"
#include "ipc_utils.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "ProfileChangeListenerStub";
}
ProfileChangeListenerStub::ProfileChangeListenerStub()
{
    HILOGI("construct!");
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD)] =
        &ProfileChangeListenerStub::OnTrustDeviceProfileAddInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_DELETE)] =
        &ProfileChangeListenerStub::OnTrustDeviceProfileDeleteInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_UPDATE)] =
        &ProfileChangeListenerStub::OnTrustDeviceProfileUpdateInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ACTIVE)] =
        &ProfileChangeListenerStub::OnTrustDeviceProfileActiveInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_INACTIVE)] =
        &ProfileChangeListenerStub::OnTrustDeviceProfileInactiveInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_ADD)] =
        &ProfileChangeListenerStub::OnDeviceProfileAddInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_DELETE)] =
        &ProfileChangeListenerStub::OnDeviceProfileDeleteInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_UPDATE)] =
        &ProfileChangeListenerStub::OnDeviceProfileUpdateInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_ADD)] =
        &ProfileChangeListenerStub::OnServiceProfileAddInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_DELETE)] =
        &ProfileChangeListenerStub::OnServiceProfileDeleteInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_UPDATE)] =
        &ProfileChangeListenerStub::OnServiceProfileUpdateInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_ADD)] =
        &ProfileChangeListenerStub::OnCharacteristicProfileAddInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_DELETE)] =
        &ProfileChangeListenerStub::OnCharacteristicProfileDeleteInner;
    funcsMap_[static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_UPDATE)] =
        &ProfileChangeListenerStub::OnCharacteristicProfileUpdateInner;
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
        case static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ADD):
            return ProfileChangeListenerStub::OnTrustDeviceProfileAddInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_DELETE):
            return ProfileChangeListenerStub::OnTrustDeviceProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_UPDATE):
            return ProfileChangeListenerStub::OnTrustDeviceProfileUpdateInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_ACTIVE):
            return ProfileChangeListenerStub::OnTrustDeviceProfileActiveInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_TRUST_DEVICE_PROFILE_INACTIVE):
            return ProfileChangeListenerStub::OnTrustDeviceProfileInactiveInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_ADD):
            return ProfileChangeListenerStub::OnDeviceProfileAddInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_DELETE):
            return ProfileChangeListenerStub::OnDeviceProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_DEVICE_PROFILE_UPDATE):
            return ProfileChangeListenerStub::OnDeviceProfileUpdateInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_ADD):
            return ProfileChangeListenerStub::OnServiceProfileAddInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_DELETE):
            return ProfileChangeListenerStub::OnServiceProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_SERVICE_PROFILE_UPDATE):
            return ProfileChangeListenerStub::OnServiceProfileUpdateInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_ADD):
            return ProfileChangeListenerStub::OnCharacteristicProfileAddInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_DELETE):
            return ProfileChangeListenerStub::OnCharacteristicProfileDeleteInner(data, reply);
        case static_cast<uint32_t>(DPInterfaceCode::ON_CHAR_PROFILE_UPDATE):
            return ProfileChangeListenerStub::OnCharacteristicProfileUpdateInner(data, reply);
        default:
            HILOGW("unknown request code, please check, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
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
} // namespace DistributedDeviceProfile
} // namespace OHOS
