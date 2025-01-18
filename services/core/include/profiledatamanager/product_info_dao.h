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

#ifndef OHOS_DP_PRODUCT_INFO_DAO_H
#define OHOS_DP_PRODUCT_INFO_DAO_H

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "product_info.h"
#include "profile_data_rdb_adapter.h"
#include "single_instance.h"
#include "values_bucket.h"

namespace OHOS {
namespace DistributedDeviceProfile {
using namespace OHOS::NativeRdb;

class ProductInfoDao {
    DECLARE_SINGLE_INSTANCE(ProductInfoDao);

public:
    int32_t Init();
    int32_t UnInit();
    int32_t PutProductInfo(const ProductInfo& productInfo);
    int32_t GetProductInfos(const std::vector<std::string>& productIds,
        std::vector<ProductInfo>& productInfos);
    int32_t DeleteProductInfo(const ProductInfo& productInfo);
    int32_t UpdateProductInfo(const ProductInfo& productInfo);
    int32_t CreateTable();
    int32_t CreateIndex();
    bool CreateQuerySqlAndCondition(const std::vector<std::string>& productIds,
        std::string& sql, std::vector<ValueObject>& condition);
    int32_t ProductInfoToEntries(const ProductInfo& productInfo, ValuesBucket& values);
    int32_t ConvertToProductInfo(std::shared_ptr<ResultSet> resultSet, ProductInfo& productInfo);
private:
    std::mutex rdbMutex_;
};
} // DistributedDeviceProfile
} // OHOS
#endif // OHOS_DP_PRODUCT_INFO_DAO_H
