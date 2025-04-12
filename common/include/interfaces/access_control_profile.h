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

#ifndef OHOS_DP_ACCESS_CONTROL_PROFILE_H
#define OHOS_DP_ACCESS_CONTROL_PROFILE_H

#include <string>

#include "accesser.h"
#include "accessee.h"
#include "distributed_device_profile_enums.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class AccessControlProfile : public DpParcel {
public:
    AccessControlProfile();
    ~AccessControlProfile() = default;

public:
    int64_t GetAccessControlId() const;
    void SetAccessControlId(int64_t accessControlId);
    int64_t GetAccesserId() const;
    void SetAccesserId(int64_t accesserId);
    int64_t GetAccesseeId() const;
    void SetAccesseeId(int64_t accesseeId);
    std::string GetSessionKey() const;
    void SetSessionKey(const std::string& sessionKey);
    std::string GetTrustDeviceId() const;
    void SetTrustDeviceId(const std::string& trustDeviceId);
    uint32_t GetBindType() const;
    void SetBindType(uint32_t bindType);
    uint32_t GetAuthenticationType() const;
    void SetAuthenticationType(uint32_t authenticationType);
    int32_t GetStatus() const;
    void SetStatus(int32_t status);
    int64_t GetValidPeriod() const;
    void SetValidPeriod(int64_t validPeriod);
    int64_t GetLastAuthTime() const;
    void SetLastAuthTime(int64_t lastAuthTime);
    Accesser GetAccesser() const;
    void SetAccesser(const Accesser &accesser);
    Accessee GetAccessee() const;
    void SetAccessee(const Accessee &accessee);
    uint32_t GetBindLevel() const;
    void SetBindLevel(uint32_t bindLevel);
    uint32_t GetDeviceIdType() const;
    void SetDeviceIdType(uint32_t deviceIdType);
    std::string GetDeviceIdHash() const;
    void SetDeviceIdHash(const std::string& deviceIdHash);
    std::string GetExtraData() const;
    void SetExtraData(const std::string& extraData);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int64_t accessControlId_;
    int64_t accesserId_;
    int64_t accesseeId_;
    std::string sessionKey_;
    uint32_t bindType_;
    uint32_t authenticationType_;
    uint32_t bindLevel_;
    int32_t status_;
    int64_t validPeriod_;
    int64_t lastAuthTime_;
    std::string trustDeviceId_;
    uint32_t deviceIdType_;
    std::string deviceIdHash_;
    std::string extraData_;
    Accesser accesser_;
    Accessee accessee_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_ACCESS_CONTROL_PROFILE_H
