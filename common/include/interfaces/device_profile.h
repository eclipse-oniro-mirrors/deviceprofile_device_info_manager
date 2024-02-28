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

#ifndef OHOS_DP_DEVICE_PROFILE_H
#define OHOS_DP_DEVICE_PROFILE_H

#include <cstdint>
#include <string>
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceProfile : public DpParcel {
public:
    DeviceProfile()
        : deviceId_(""),
        deviceTypeName_(""),
        deviceTypeId_(0),
        deviceName_(""),
        manufactureName_(""),
        deviceModel_(""),
        storageCapability_(0),
        osSysCap_(""),
        osApiLevel_(0),
        osVersion_(""),
        osType_(0)
    {}
    ~DeviceProfile() = default;

    std::string GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    std::string GetDeviceTypeName() const;
    void SetDeviceTypeName(const std::string& deviceTypeName);
    int32_t GetDeviceTypeId() const;
    void SetDeviceTypeId(int32_t deviceTypeId);
    std::string GetDeviceName() const;
    void SetDeviceName(const std::string& deviceName);
    std::string GetManufactureName() const;
    void SetManufactureName(std::string manufactureName);
    std::string GetDeviceModel() const;
    void SetDeviceModel(const std::string& deviceModel);
    int64_t GetStorageCapability() const;
    void SetStorageCapability(int64_t storageCapability);
    std::string GetOsSysCap() const;
    void SetOsSysCap(const std::string& osSysCap);
    int32_t GetOsApiLevel() const;
    void SetOsApiLevel(int32_t osApiLevel);
    std::string GetOsVersion() const;
    void SetOsVersion(const std::string& osVersion);
    int32_t GetOsType() const;
    void SetOsType(int32_t osType);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    bool operator!=(const DeviceProfile& deviceProfile) const;
    std::string dump() const override;

private:
    std::string deviceId_;
    std::string deviceTypeName_;
    int32_t deviceTypeId_;
    std::string deviceName_;
    std::string manufactureName_;
    std::string deviceModel_;
    int64_t storageCapability_;
    std::string osSysCap_;
    int32_t osApiLevel_;
    std::string osVersion_;
    int32_t osType_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_DEVICE_PROFILE_H
