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

#ifndef OHOS_DP_BUSINESS_EVENT_H
#define OHOS_DP_BUSINESS_EVENT_H

#include <cstdint>
#include <string>

#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"
#include "parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class BusinessEvent : public DpParcel {
public:
    BusinessEvent(const std::string& businessKey, const std::string& businessValue)
        : businessKey_(businessKey), businessValue_(businessValue) {};
        
    BusinessEvent();
    ~BusinessEvent();

    std::string GetBusinessKey() const;
    void SetBusinessKey(const std::string& businessKey);
    std::string GetBusinessValue() const;
    void SetBusinessValue(const std::string& businessValue);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    std::string dump() const override;

private:
    std::string businessKey_ = "";
    std::string businessValue_ = "";
};

class BusinessEventExt : public Parcelable {
public:
    BusinessEventExt(const std::string& businessKey, const std::string& businessValue)
        : businessKey_(businessKey), businessValue_(businessValue) {};

    BusinessEventExt();
    ~BusinessEventExt();

    std::string GetBusinessKey() const;
    void SetBusinessKey(const std::string& businessKey);
    std::string GetBusinessValue() const;
    void SetBusinessValue(const std::string& businessValue);
    bool Marshalling(Parcel &parcel) const override;
    static BusinessEventExt *Unmarshalling(Parcel &parcel);

private:
    std::string businessKey_ = "";
    std::string businessValue_ = "";
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_BUSINESS_EVENT_H

