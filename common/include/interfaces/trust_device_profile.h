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

#ifndef OHOS_DP_TRUST_DEVICE_PROFILE_H
#define OHOS_DP_TRUST_DEVICE_PROFILE_H

#include <string>
#include "distributed_device_profile_enums.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class TrustDeviceProfile : public DpParcel {
public:
    TrustDeviceProfile()
        : deviceId_(""),
        deviceIdType_((uint32_t)DeviceIdType::MIN),
        deviceIdHash_(""),
        status_((uint32_t)Status::MIN)
    {}
    ~TrustDeviceProfile() = default;

    std::string GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    int32_t GetDeviceIdType() const;
    void SetDeviceIdType(int32_t deviceType);
    std::string GetDeviceIdHash() const;
    void SetDeviceIdHash(const std::string& deviceIdHash);
    int32_t GetStatus() const;
    void SetStatus(int32_t status);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string deviceId_;
    uint32_t deviceIdType_;
    std::string deviceIdHash_;
    uint32_t status_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_TRUST_DEVICE_PROFILE_H
