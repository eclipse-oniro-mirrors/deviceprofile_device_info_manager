/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_ACCESSEE_H
#define OHOS_DP_ACCESSEE_H

#include <cstdint>
#include <string>
#include "distributed_device_profile_enums.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class Accessee : public DpParcel {
public:
    Accessee();
    ~Accessee() = default;

public:
    int64_t GetAccesseeId();
    void SetAccesseeId(int64_t accesseeId);
    std::string GetAccesseeDeviceId() const;
    void SetAccesseeDeviceId(const std::string& accesseeDeviceId);
    int32_t GetAccesseeUserId() const;
    void SetAccesseeUserId(int32_t accesseeUserId);
    std::string GetAccesseeAccountId() const;
    void SetAccesseeAccountId(const std::string& accesseeAccountId);
    int64_t GetAccesseeTokenId() const;
    void SetAccesseeTokenId(int64_t accesseeTokenId);
    std::string GetAccesseeBundleName() const;
    void SetAccesseeBundleName(const std::string& accesseeBundleName);
    std::string GetAccesseeHapSignature() const;
    void SetAccesseeHapSignature(const std::string& accesseeHapSignature);
    uint32_t GetAccesseeBindLevel() const;
    void SetAccesseeBindLevel(uint32_t accesseeBindLevel);
    std::string GetAccesseeDeviceName() const;
    void SetAccesseeDeviceName(const std::string& accesseeDeviceName);
    std::string GetAccesseeServiceName() const;
    void SetAccesseeServiceName(std::string accesseeServiceName);
    int32_t GetAccesseeCredentialId() const;
    void SetAccesseeCredentialId(int32_t accesseeCredentialId);
    int32_t GetAccesseeStatus() const;
    void SetAccesseeStatus(int32_t accesseeStatus);
    int32_t GetAccesseeSessionKeyId() const;
    void SetAccesseeSessionKeyId(int32_t accesseeSessionKeyId);
    int64_t GetAccesseeSKTimeStamp() const;
    void SetAccesseeSKTimeStamp(int64_t accesseeSKTimeStamp);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int64_t accesseeId_;
    std::string accesseeDeviceId_;
    int32_t accesseeUserId_;
    std::string accesseeAccountId_;
    int64_t accesseeTokenId_;
    std::string accesseeBundleName_;
    std::string accesseeHapSignature_;
    uint32_t accesseeBindLevel_;
    std::string accesseeDeviceName_;
    std::string accesseeServiceName_;
    int32_t accesseeCredentialId_;
    int32_t accesseeStatus_;
    int32_t accesseeSessionKeyId_;
    int64_t accesseeSKTimeStamp_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_ACCESSEE_H
