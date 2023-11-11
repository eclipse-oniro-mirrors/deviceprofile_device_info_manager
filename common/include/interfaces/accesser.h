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
    Accesser()
        : accesserId_(0),
        accesserDeviceId_(""),
        accesserUserId_(-1),
        accesserAccountId_(""),
        accesserTokenId_(-1),
        accesserBundleName_(""),
        accesserHapSignature_(""),
        accesserBindLevel_((uint32_t)BindLevel::MIN)
    {}
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
    int32_t GetAccesserBindLevel() const;
    void SetAccesserBindLevel(int32_t accesserBindLevel);
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
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_ACCESSER_H
