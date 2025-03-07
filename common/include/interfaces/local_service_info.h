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

#ifndef OHOS_DP_LOCAL_SERVICE_INFO_H
#define OHOS_DP_LOCAL_SERVICE_INFO_H

#include <cstdint>
#include <string>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class LocalServiceInfo : public DpParcel {
public:
    LocalServiceInfo(const std::string& bundleName,
        const int32_t authBoxType, const int32_t authType, const int32_t pinExchangeType,
        const std::string& pinCode, const std::string& description,
        const std::string& extraInfo)
        : bundleName_(bundleName),
        authBoxType_(authBoxType),
        authType_(authType),
        pinExchangeType_(pinExchangeType),
        pinCode_(pinCode),
        description_(description),
        extraInfo_(extraInfo)
    {}
    LocalServiceInfo();
    ~LocalServiceInfo();

    std::string GetBundleName() const;
    void SetBundleName(const std::string& bundleName);
    int32_t GetAuthBoxType() const;
    void SetAuthBoxType(const int32_t authBoxType);
    int32_t GetAuthType() const;
    void SetAuthType(const int32_t authType);
    int32_t GetPinExchangeType() const;
    void SetPinExchangeType(const int32_t pinExchangeType);
    std::string GetPinCode() const;
    void SetPinCode(const std::string& pinCode);
    std::string GetDescription() const;
    void SetDescription(const std::string& description);
    std::string GetExtraInfo() const;
    void SetExtraInfo(const std::string& extraInfo);

    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string bundleName_ = "";
    int32_t authBoxType_ = DEFAULT_AUTH_BOX_TYPE;
    int32_t authType_ = DEFAULT_AUTH_TYPE;
    int32_t pinExchangeType_ = DEFAULT_PIN_EXCHANGE_TYPE;
    std::string pinCode_ = "";
    std::string description_ = "";
    std::string extraInfo_ = "";
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_SERVICE_INFO_PROFILE_H
