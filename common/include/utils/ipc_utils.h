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

#ifndef OHOS_DP_IPC_SERIALIZATION_UTILS_H
#define OHOS_DP_IPC_SERIALIZATION_UTILS_H

#include <map>
#include <string>
#include <vector>

#include "message_parcel.h"
#include "parcel.h"

#include "access_control_profile.h"
#include "accessee.h"
#include "accesser.h"
#include "characteristic_profile.h"
#include "device_icon_info.h"
#include "device_profile.h"
#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_subscribe_info.h"
#include "product_info.h"
#include "service_info_profile.h"
#include "service_info_profile_new.h"
#include "service_profile.h"
#include "trust_device_profile.h"
#include "trusted_device_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class IpcUtils {
public:
    static bool Marshalling(MessageParcel& parcel, const std::vector<TrustDeviceProfile>& trustDeviceProfiles);
    static bool Marshalling(MessageParcel& parcel, const std::vector<AccessControlProfile>& aclProfiles);
    static bool Marshalling(MessageParcel& parcel, const std::vector<DeviceProfile>& deviceProfiles);
    static bool Marshalling(MessageParcel& parcel, const std::vector<ServiceProfile>& serviceProfiles);
    static bool Marshalling(MessageParcel& parcel, const std::vector<CharacteristicProfile>& charProfiles);
    static bool Marshalling(MessageParcel& parcel, const std::vector<std::string>& strings);
    static bool Marshalling(MessageParcel& parcel, const std::vector<int32_t>& params);
    static bool Marshalling(MessageParcel& parcel, const std::vector<uint8_t>& params);
    static bool Marshalling(MessageParcel& parcel, const std::map<std::string, std::string>& params);
    static bool Marshalling(MessageParcel& parcel, const std::map<std::string,
        OHOS::DistributedDeviceProfile::SubscribeInfo>& listenerMap);
    static bool Marshalling(MessageParcel& parcel, const std::unordered_set<ProfileChangeType>& changeTypes);
    static bool Marshalling(MessageParcel& parcel, const std::vector<TrustedDeviceInfo>& deviceInfos);
    static bool Marshalling(MessageParcel& parcel, const std::vector<DeviceIconInfo>& deviceIconInfos);
    static bool Marshalling(MessageParcel& parcel, const std::vector<ProductInfo>& productInfos);
    static bool Marshalling(MessageParcel& parcel, const std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<ServiceInfoProfile>& serviceInfoProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<ProductInfo>& productInfos);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<DeviceIconInfo>& deviceIconInfos);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<TrustDeviceProfile>& trustDeviceProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<AccessControlProfile>& aclProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<DeviceProfile>& deviceProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<ServiceProfile>& serviceProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<CharacteristicProfile>& charProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<std::string>& strings);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<int32_t>& params);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<uint8_t>& params);
    static bool UnMarshalling(MessageParcel& parcel, std::map<std::string, std::string>& params);
    static bool UnMarshalling(MessageParcel& parcel, std::map<std::string,
        OHOS::DistributedDeviceProfile::SubscribeInfo>& listenerMap);
    static bool UnMarshalling(MessageParcel& parcel, std::unordered_set<ProfileChangeType>& changeTypes);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<TrustedDeviceInfo>& deviceInfos);
    static bool Marshalling(MessageParcel& parcel, const std::vector<ServiceInfoProfileNew>& serviceInfoProfiles);
    static bool UnMarshalling(MessageParcel& parcel, std::vector<ServiceInfoProfileNew>& serviceInfoProfiles);
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_IPC_SERIALIZATION_UTILS_H
