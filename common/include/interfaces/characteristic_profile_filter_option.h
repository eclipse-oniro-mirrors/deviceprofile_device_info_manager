/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_CHARACTERISTIC_PROFILE_FILTER_OPTION_H
#define OHOS_DP_CHARACTERISTIC_PROFILE_FILTER_OPTION_H

#include <cstdint>
#include <string>
#include <vector>
#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class CharacteristicProfileFilterOption : public DpParcel {
public:
    CharacteristicProfileFilterOption(const int32_t userId, const std::string& accountld,
        const std::string& deviceId, const std::string& wiseDeviceId,
        const std::string& serviceId, const std::string& characteristicKey,
        const std::vector<int32_t>& characteristicProfileIds, const int32_t serviceProfileId)
        : userId_(userId),
        accountld_(accountld),
        deviceId_(deviceId),
        wiseDeviceId_(wiseDeviceId),
        serviceId_(serviceId),
        characteristicKey_(characteristicKey),
        characteristicProfileIds_(characteristicProfileIds),
        serviceProfileId_(serviceProfileId)
    {}
    CharacteristicProfileFilterOption() = default;
    ~CharacteristicProfileFilterOption() = default;

    std::string GetAccountld() const;
    void SetAccountld(const std::string& accountld);
    std::string GetServiceId() const;
    void SetServiceId(const std::string& serviceId);
    std::string GetWiseDeviceId() const;
    void SetWiseDeviceId(const std::string& wiseDeviceId);
    int32_t GetUserId() const;
    void SetUserId(int32_t userId);
    std::vector<int32_t> GetCharacteristicProfileIds() const;
    void SetCharacteristicProfileIds(std::vector<int32_t>& characteristicProfileIds);
    std::string GetCharacteristicKey() const;
    void SetCharacteristicKey(std::string& characteristicKey);
    std::string GetDeviceId() const;
    void SetDeviceId(std::string& deviceId);
    int32_t GetServiceProfileId() const;
    void SetServiceProfileId(int32_t serviceProfileId);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int32_t userId_ = DEFAULT_USER_ID;
    std::string accountld_ = "";
    std::string deviceId_ = "";
    std::string wiseDeviceId_ = "";
    std::string serviceId_ = "";
    std::string characteristicKey_ = "";
    std::vector<int32_t> characteristicProfileIds_;
    int32_t serviceProfileId_ = DEFAULT_SERVICE_PROFILE_ID;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_CHARACTERISTIC_PROFILE_FILTER_OPTION_H
