/*
 * Copyright (c) 2024  Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_TRUSTED_DEVICE_INFO_H
#define OHOS_DP_TRUSTED_DEVICE_INFO_H

#include <string>
#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class TrustedDeviceInfo : public DpParcel {
public:
    TrustedDeviceInfo() : networkId_(""), authForm_(BINDTYPE_INIT), deviceTypeId_(0),
        osVersion_(""), osType_(0), udid_(""), uuid_("")
    {}
    ~TrustedDeviceInfo() = default;

    std::string GetNetworkId() const;
    void SetNetworkId(const std::string& networkId);
    int32_t GetAuthForm() const;
    void SetAuthForm(int32_t authForm);
    uint16_t GetDeviceTypeId() const;
    void SetDeviceTypeId(uint16_t deviceTypeId);
    std::string GetOsVersion() const;
    void SetOsVersion(const std::string& osVersion);
    int32_t GetOsType() const;
    void SetOsType(int32_t osType);
    std::string GetUdid() const;
    void SetUdid(const std::string& udid);
    std::string GetUuid() const;
    void SetUuid(const std::string& uuid);

    bool operator!=(const TrustedDeviceInfo& trustedDeviceInfo) const;
    bool operator<(const TrustedDeviceInfo& trustedDeviceInfo) const;
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string networkId_;
    std::int32_t authForm_;
    std::uint16_t deviceTypeId_;
    std::string osVersion_;
    std::int32_t osType_;
    std::string udid_;
    std::string uuid_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_TRUSTED_DEVICE_INFO_H
