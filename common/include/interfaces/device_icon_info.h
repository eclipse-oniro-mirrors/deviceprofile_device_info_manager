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

#ifndef OHOS_DP_DEVICE_ICON_INFO_H
#define OHOS_DP_DEVICE_ICON_INFO_H

#include <string>
#include <vector>

#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceIconInfo : public DpParcel {
public:
    DeviceIconInfo()
        : id_(0),
        productId_(""),
        internalModel_(""),
        subProductId_(""),
        imageType_(""),
        specName_(""),
        modifyTime_(0)
    {}
    ~DeviceIconInfo() = default;
    int32_t GetId() const;
    void SetId(const int32_t id);
    std::string GetProductId() const;
    void SetProductId(const std::string& productId);
    std::string GetSubProductId() const;
    void SetSubProductId(const std::string& subProductId);
    std::string GetInternalModel() const;
    void SetInternalModel(const std::string& internalModel);
    std::string GetImageType() const;
    void SetImageType(const std::string& imageType);
    std::string GetSpecName() const;
    void SetSpecName(const std::string& specName);
    std::string GetVersion() const;
    void SetVersion(const std::string& version);
    std::string GetWiseVersion() const;
    void SetWiseVersion(const std::string& wiseVersion);
    std::string GetUrl() const;
    void SetUrl(const std::string& url);
    std::vector<uint8_t> GetIcon() const;
    void SetIcon(const std::vector<uint8_t>& icon);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    bool operator!=(const DeviceIconInfo& other) const;
    std::string dump() const override;
    std::string GetUniqueKey() const;
    int64_t GetModifyTime() const;
    void SetModifyTime(int64_t modifyTime);

private:
    int32_t id_;
    std::string productId_;
    std::string internalModel_;
    std::string subProductId_;
    std::string imageType_;
    std::string specName_;
    std::string version_;
    std::string wiseVersion_;
    std::string url_;
    std::vector<uint8_t> icon_;
    int64_t modifyTime_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_DEVICE_ICON_INFO_H
