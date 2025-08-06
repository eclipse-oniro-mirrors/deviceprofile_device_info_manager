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

#ifndef OHOS_DP_PRODUCT_INFO_H
#define OHOS_DP_PRODUCT_INFO_H

#include <string>
#include <vector>

#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class ProductInfo : public DpParcel {
public:
    ProductInfo() : productId_(""),
        model_(""),
        productName_(""),
        productShortName_(""),
        imageVersion_("")
    {}
    ~ProductInfo() = default;

    std::string GetProductId() const;
    void SetProductId(const std::string& productId);
    std::string GetModel() const;
    void SetModel(const std::string& model);
    std::string GetProductName() const;
    void SetProductName(const std::string& productName);
    std::string GetProductShortName() const;
    void SetProductShortName(const std::string& productShortName);
    std::string GetImageVersion() const;
    void SetImageVersion(const std::string& imageVersion);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    bool operator!=(const ProductInfo& other) const;
    std::string dump() const override;

private:
    std::string GetAnonyProductName(const std::string& value) const;

    std::string productId_;
    std::string model_;
    std::string productName_;
    std::string productShortName_;
    std::string imageVersion_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif //OHOS_DP_PRODUCT_INFO_H
