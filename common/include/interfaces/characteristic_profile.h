/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_CHARACTERISTIC_PROFILE_H
#define OHOS_DP_CHARACTERISTIC_PROFILE_H

#include <cstdint>
#include <string>
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class CharacteristicProfile : public DpParcel {
public:
    CharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, const std::string& characteristicValue)
        : deviceId_(deviceId),
        serviceName_(serviceName),
        characteristicKey_(characteristicKey),
        characteristicValue_(characteristicValue)
    {}
    CharacteristicProfile() = default;
    ~CharacteristicProfile() = default;

    std::string GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    std::string GetServiceName() const;
    void SetServiceName(const std::string& serviceName);
    std::string GetCharacteristicKey() const;
    void SetCharacteristicKey(const std::string& characteristicId);
    std::string GetCharacteristicValue() const;
    void SetCharacteristicValue(const std::string& characteristicValue);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    bool operator!=(const CharacteristicProfile& charProfile) const;
    void dump() const override;

private:
    std::string deviceId_ = "";
    std::string serviceName_ = "";
    std::string characteristicKey_ = "";
    std::string characteristicValue_ = "";
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_CHARACTERISTIC_PROFILE_H
