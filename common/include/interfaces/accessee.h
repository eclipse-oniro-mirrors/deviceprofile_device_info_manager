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
    Accessee()
        : accesseeId_(0),
        accesseeDeviceId_(""),
        accesseeUserId_(-1),
        accesseeAccountId_(""),
        accesseeTokenId_(-1),
        accesseeBundleName_(""),
        accesseeHapSignature_(""),
        accesseeBindLevel_((uint32_t)BindLevel::MIN)
    {}
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
    int32_t GetAccesseeBindLevel() const;
    void SetAccesseeBindLevel(int32_t accesseeBindLevel);
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
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_ACCESSEE_H
