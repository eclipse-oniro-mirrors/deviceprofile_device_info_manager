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

#ifndef OHOS_DP_ACCESSER_H
#define OHOS_DP_ACCESSER_H

#include <cstdint>
#include <string>
#include "distributed_device_profile_enums.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class Accesser : public DpParcel {
public:
    Accesser();
    ~Accesser() = default;

    int64_t GetAccesserId();
    void SetAccesserId(int64_t accesserId);
    std::string GetAccesserDeviceId() const;
    void SetAccesserDeviceId(const std::string& accesserDeviceId);
    int32_t GetAccesserUserId() const;
    void SetAccesserUserId(int32_t accesserUserId);
    std::string GetAccesserAccountId() const;
    void SetAccesserAccountId(const std::string& accesserAccountId);
    int64_t GetAccesserTokenId() const;
    void SetAccesserTokenId(int64_t accesserTokenId);
    std::string GetAccesserBundleName() const;
    void SetAccesserBundleName(const std::string& accesserBundleName);
    std::string GetAccesserHapSignature() const;
    void SetAccesserHapSignature(const std::string& accesserHapSignature);
    uint32_t GetAccesserBindLevel() const;
    void SetAccesserBindLevel(uint32_t accesserBindLevel);
    std::string GetAccesserDeviceName() const;
    void SetAccesserDeviceName(const std::string& accesserDeviceName);
    std::string GetAccesserServiceName() const;
    void SetAccesserServiceName(const std::string& accesserServiceName);
    int32_t GetAccesserCredentialId() const;
    void SetAccesserCredentialId(int32_t accesserCredentialId);
    int32_t GetAccesserStatus() const;
    void SetAccesserStatus(int32_t accesserStatus);
    int32_t GetAccesserSessionKeyId() const;
    void SetAccesserSessionKeyId(int32_t accesserSessionKeyId);
    int64_t GetAccesserSKTimeStamp() const;
    void SetAccesserSKTimeStamp(int64_t accesserSKTimeStamp);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int64_t accesserId_;
    std::string accesserDeviceId_;
    int32_t accesserUserId_;
    std::string accesserAccountId_;
    int64_t accesserTokenId_;
    std::string accesserBundleName_;
    std::string accesserHapSignature_;
    uint32_t accesserBindLevel_;
    std::string accesserDeviceName_;
    std::string accesserServiceName_;
    int32_t accesserCredentialId_;
    int32_t accesserStatus_;
    int32_t accesserSessionKeyId_;
    int64_t accesserSKTimeStamp_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_ACCESSER_H
