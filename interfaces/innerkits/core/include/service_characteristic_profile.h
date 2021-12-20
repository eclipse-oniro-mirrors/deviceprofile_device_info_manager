/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_SERVICE_PROFILE_CHARACTERISTIC_PROFILE_H
#define OHOS_DEVICE_SERVICE_PROFILE_CHARACTERISTIC_PROFILE_H

#include "parcel.h"

namespace OHOS {
namespace DeviceProfile {
class ServiceCharacteristicProfile : public Parcelable {
public:
    ServiceCharacteristicProfile() = default;
    ~ServiceCharacteristicProfile() = default;

    void SetServiceId(const std::string& serviceId);
    void SetServiceType(const std::string& serviceType);
    void SetServiceProfileJson(const std::string& profileJson);
    void SetCharacteristicProfileJson(const std::string& profileJson);

    const std::string& GetServiceId() const;
    const std::string& GetServiceType() const;
    const std::string& GetServiceProfileJson() const;
    const std::string& GetCharacteristicProfileJson() const;

    bool Marshalling(Parcel& parcel) const override;
    bool Unmarshalling(Parcel& parcel);

private:
    std::string serviceId_;
    std::string serviceType_;
    // reserved, not used currently
    std::string serviceProfileJson_;
    std::string characteristicProfileJson_;
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DEVICE_SERVICE_PROFILE_CHARACTERISTIC_PROFILE_H