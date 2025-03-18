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

#ifndef OHOS_DP_QUERY_PROFILE_H
#define OHOS_DP_QUERY_PROFILE_H

#include <string>
#include "distributed_device_profile_enums.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class QueryProfile : public DpParcel {
public:
    QueryProfile();
    ~QueryProfile() = default;

    std::string GetAccesserDeviceId() const;
    void SetAccesserDeviceId(const std::string& accesserDeviceId);
    int32_t GetAccesserUserId() const;
    void SetAccesserUserId(int32_t accesserUserId);
    std::string GetAccesserAccountId() const;
    void SetAccesserAccountId(const std::string& accesserAccountId);
    int64_t GetAccesserTokenId() const;
    void SetAccesserTokenId(int64_t accesserTokenId);
    std::string GetAccesseeDeviceId() const;
    void SetAccesseeDeviceId(const std::string& accesseeDeviceId);
    int32_t GetAccesseeUserId() const;
    std::string GetAccesseeAccountId() const;
    void SetAccesseeAccountId(const std::string& accesseeAccountId);
    void SetAccesseeUserId(int32_t accesseeUserId);
    int64_t GetAccesseeTokenId() const;
    void SetAccesseeTokenId(int64_t accesseeTokenId);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string accesserDeviceId_;
    int32_t accesserUserId_;
    std::string accesserAccountId_;
    int64_t accesserTokenId_;
    std::string accesseeDeviceId_;
    int32_t accesseeUserId_;
    std::string accesseeAccountId_;
    int64_t accesseeTokenId_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_QUERY_PROFILE_H
