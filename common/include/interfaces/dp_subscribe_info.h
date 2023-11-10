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

#ifndef OHOS_DP_SUBSCRIBER_INFO_H
#define OHOS_DP_SUBSCRIBER_INFO_H

#include <string>
#include <memory>
#include "dp_parcel.h"
#include "macro_utils.h"
#include "iremote_broker.h"
#include "i_profile_change_listener.h"
#include "distributed_device_profile_constants.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class SubscribeInfo : public DpParcel {
public:
    SubscribeInfo(int32_t saId, const std::string& subscribeKey,
        std::unordered_set<ProfileChangeType> subscribeChangeTypes, sptr<IProfileChangeListener> profileChangeListener);
    SubscribeInfo();
    ~SubscribeInfo();

    int32_t GetSaId() const;
    void SetSaId(int32_t saId);
    std::string GetSubscribeKey() const;
    void SetSubscribeKey(const std::string& deviceId, const std::string& deviceAttribute);
    void SetSubscribeKey(const std::string& deviceId, const std::string& serviceName,
        const std::string& serviceAttribute);
    void SetSubscribeKey(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicKey, const std::string& characteristicAttribute);
    // subscribeTrustDeviceProfile
    void SetSubscribeKey(const std::string& subscribeKey);
    sptr<IRemoteObject> GetListener() const;
    void SetListener(sptr<IProfileChangeListener> listener);
    std::unordered_set<ProfileChangeType> GetProfileChangeTypes() const;
    void AddProfileChangeType(ProfileChangeType profileChangeType);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    int32_t saId_ = -1;
    std::string subscribeKey_ = "";
    std::unordered_set<ProfileChangeType> subscribeChangeTypes_;
    sptr<IRemoteObject> listener_ = nullptr;
};

class SubscribeCompare {
public:
    SubscribeCompare() = default;
    ~SubscribeCompare() = default;

    int operator()(const SubscribeInfo& one, const SubscribeInfo& other) const
    {
        return (one.GetSaId() == other.GetSaId()) && (one.GetSubscribeKey() == other.GetSubscribeKey());
    }
};

class SubscribeHash {
public:
    SubscribeHash() = default;
    ~SubscribeHash() = default;
    int operator()(const SubscribeInfo& subscriberInfo) const
    {
        return subscriberInfo.GetSaId();
    }
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_SUBSCRIBER_INFO_H
