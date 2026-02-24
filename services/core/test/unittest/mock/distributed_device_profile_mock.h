/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_UTTEST_DISTRIBUTED_DEVICE_PROFILE_MOCK_H
#define OHOS_UTTEST_DISTRIBUTED_DEVICE_PROFILE_MOCK_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <gmock/gmock.h>
#include "iremote_broker.h"
#include "i_distributed_device_profile.h"
#include "service_info.h"
#include "user_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {

// Type alias to avoid MOCK_METHOD parsing issues with complex types
using SubscribeInfoMap = std::map<std::string, SubscribeInfo>;

class IDistributedDeviceProfileMock : public IDistributedDeviceProfile {
public:
    IDistributedDeviceProfileMock() = default;
    virtual ~IDistributedDeviceProfileMock() = default;

    MOCK_METHOD(int32_t, PutAccessControlProfile, (const AccessControlProfile&), (override));
    MOCK_METHOD(int32_t, UpdateAccessControlProfile, (const AccessControlProfile&), (override));
    MOCK_METHOD(int32_t, GetTrustDeviceProfile, (const std::string&, TrustDeviceProfile&), (override));
    MOCK_METHOD(int32_t, GetAllTrustDeviceProfile, (std::vector<TrustDeviceProfile>&), (override));
    MOCK_METHOD(int32_t, GetAccessControlProfile,
        ((std::map<std::string, std::string>), (std::vector<AccessControlProfile>&)), (override));
    MOCK_METHOD(int32_t, GetAllAccessControlProfile, (std::vector<AccessControlProfile>&), (override));
    MOCK_METHOD(int32_t, GetAllAclIncludeLnnAcl, (std::vector<AccessControlProfile>&), (override));
    MOCK_METHOD(int32_t, DeleteAccessControlProfile, (int32_t), (override));
    MOCK_METHOD(int32_t, PutSessionKey,
        (uint32_t, const std::vector<uint8_t>&, int32_t&), (override));
    MOCK_METHOD(int32_t, GetSessionKey,
        (uint32_t, int32_t, std::vector<uint8_t>&), (override));
    MOCK_METHOD(int32_t, UpdateSessionKey,
        (uint32_t, int32_t, const std::vector<uint8_t>&), (override));
    MOCK_METHOD(int32_t, DeleteSessionKey, (uint32_t, int32_t), (override));
    MOCK_METHOD(int32_t, PutDeviceProfileBatch, (std::vector<DeviceProfile>&), (override));
    MOCK_METHOD(int32_t, PutServiceProfile, (const ServiceProfile&), (override));
    MOCK_METHOD(int32_t, PutServiceProfileBatch, (const std::vector<ServiceProfile>&), (override));
    MOCK_METHOD(int32_t, PutCharacteristicProfile, (const CharacteristicProfile&), (override));
    MOCK_METHOD(int32_t, PutCharacteristicProfileBatch,
        (const std::vector<CharacteristicProfile>&), (override));
    MOCK_METHOD(int32_t, GetDeviceProfile, (const std::string&, DeviceProfile&), (override));
    MOCK_METHOD(int32_t, GetDeviceProfiles,
        (DeviceProfileFilterOptions&, std::vector<DeviceProfile>&), (override));
    MOCK_METHOD(int32_t, DeleteDeviceProfileBatch, (std::vector<DeviceProfile>&), (override));
    MOCK_METHOD(int32_t, GetServiceProfile,
        (const std::string&, const std::string&, ServiceProfile&), (override));
    MOCK_METHOD(int32_t, GetCharacteristicProfile,
        (const std::string&, const std::string&, const std::string&, CharacteristicProfile&), (override));
    MOCK_METHOD(int32_t, DeleteServiceProfile,
        (const std::string&, const std::string&, bool, int32_t), (override));
    MOCK_METHOD(int32_t, DeleteCharacteristicProfile,
        (const std::string&, const std::string&, const std::string&, bool, int32_t), (override));
    MOCK_METHOD(int32_t, SubscribeDeviceProfile, (const SubscribeInfo&), (override));
    MOCK_METHOD(int32_t, UnSubscribeDeviceProfile, (const SubscribeInfo&), (override));
    MOCK_METHOD(int32_t, SubscribeDeviceProfileInited, (int32_t, sptr<IRemoteObject>), (override));
    MOCK_METHOD(int32_t, UnSubscribeDeviceProfileInited, (int32_t), (override));
    MOCK_METHOD(int32_t, SubscribePinCodeInvalid,
        (const std::string&, int32_t, sptr<IRemoteObject>), (override));
    MOCK_METHOD(int32_t, UnSubscribePinCodeInvalid, (const std::string&, int32_t), (override));
    MOCK_METHOD(int32_t, SyncDeviceProfile,
        (const DpSyncOptions&, sptr<IRemoteObject>), (override));
    MOCK_METHOD(int32_t, SyncStaticProfile,
        (const DpSyncOptions&, sptr<IRemoteObject>), (override));
    MOCK_METHOD(int32_t, SendSubscribeInfos, (SubscribeInfoMap), (override));
    MOCK_METHOD(int32_t, PutAllTrustedDevices, (const std::vector<TrustedDeviceInfo>), (override));
    MOCK_METHOD(int32_t, PutProductInfoBatch, (const std::vector<ProductInfo>&), (override));
    MOCK_METHOD(int32_t, PutDeviceIconInfoBatch, (const std::vector<DeviceIconInfo>&), (override));
    MOCK_METHOD(int32_t, GetDeviceIconInfos,
        (const DeviceIconInfoFilterOptions&, std::vector<DeviceIconInfo>&), (override));
    MOCK_METHOD(int32_t, PutLocalServiceInfo, (const LocalServiceInfo&), (override));
    MOCK_METHOD(int32_t, UpdateLocalServiceInfo, (const LocalServiceInfo&), (override));
    MOCK_METHOD(int32_t, GetLocalServiceInfoByBundleAndPinType,
        (const std::string&, int32_t, LocalServiceInfo&), (override));
    MOCK_METHOD(int32_t, DeleteLocalServiceInfo, (const std::string&, int32_t), (override));
    MOCK_METHOD(int32_t, RegisterBusinessCallback,
        (const std::string&, const std::string&, sptr<IRemoteObject>), (override));
    MOCK_METHOD(int32_t, UnRegisterBusinessCallback, (const std::string&, const std::string&), (override));
    MOCK_METHOD(int32_t, PutBusinessEvent, (const BusinessEvent&), (override));
    MOCK_METHOD(int32_t, GetBusinessEvent, (BusinessEvent&), (override));

    MOCK_METHOD(int32_t, PutServiceInfo, (const ServiceInfo&), (override));
    MOCK_METHOD(int32_t, DeleteServiceInfo, (const UserInfo&), (override));
    MOCK_METHOD(int32_t, GetAllServiceInfoList, (std::vector<ServiceInfo>&), (override));
    MOCK_METHOD(int32_t, GetServiceInfosByUserInfo,
        (const UserInfo&, std::vector<ServiceInfo>&), (override));
    MOCK_METHOD(int32_t, SubscribeAllServiceInfo, (int32_t, sptr<IRemoteObject>), (override));

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

} // namespace DistributedDeviceProfile
} // namespace OHOS

#endif // OHOS_UTTEST_DISTRIBUTED_DEVICE_PROFILE_MOCK_H
