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

#include "product_info_dao.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "dp_services_constants.h"
#include "profile_data_rdb_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(ProductInfoDao);
namespace {
    const std::string TAG = "ProductInfoDao";
}

int32_t ProductInfoDao::Init()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    int32_t ret;
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        ret = ProfileDataRdbAdapter::GetInstance().Init();
        if (ret != DP_SUCCESS) {
            HILOGE("ProfileDataRdbAdapter Init failed");
            return DP_INIT_DB_FAILED;
        }
    }
    CreateTable();
    CreateIndex();
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ProductInfoDao::UnInit()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        HILOGE("ProfileDataRdbAdapter is UnInit");
        return DP_SUCCESS;
    }
    int32_t ret = ProfileDataRdbAdapter::GetInstance().UnInit();
    if (ret != DP_SUCCESS) {
        HILOGE("ProfileDataRdbAdapter UnInit failed");
        return DP_UNINIT_FAIL;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ProductInfoDao::PutProductInfo(const ProductInfo& productInfo)
{
    ValuesBucket values;
    ProductInfoToEntries(productInfo, values);
    int64_t rowId = ROWID_INIT;
    int32_t ret = RET_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        ret = ProfileDataRdbAdapter::GetInstance().Put(rowId, PRODUCT_INFO_TABLE, values);
        if (ret != DP_SUCCESS) {
            HILOGE("%{public}s insert failed", PRODUCT_INFO_TABLE.c_str());
            return DP_PUT_PRODUCT_INFO_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ProductInfoDao::GetProductInfos(const std::vector<std::string>& productIds,
    std::vector<ProductInfo>& productInfos)
{
    std::string sql;
    std::vector<ValueObject> condition;
    if (!CreateQuerySqlAndCondition(productIds, sql, condition)) {
        HILOGE("invalid params: productIds.size=%{public}zu", productIds.size());
        return DP_INVALID_PARAMS;
    }
    std::shared_ptr<ResultSet> resultSet = ProfileDataRdbAdapter::GetInstance().Get(sql, condition);
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        HILOGE("by condition not find data");
        resultSet->Close();
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        ProductInfo productInfo;
        ConvertToProductInfo(resultSet, productInfo);
        productInfos.emplace_back(productInfo);
    }
    resultSet->Close();
    if (productInfos.empty()) {
        return DP_NOT_FIND_DATA;
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ProductInfoDao::DeleteProductInfo(const ProductInfo& productInfo)
{
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t deleteRows = DELETEROWS_INIT;
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Delete(deleteRows, PRODUCT_INFO_TABLE,
            PRODUCT_ID + " = ?", std::vector<ValueObject>{ ValueObject(productInfo.GetProductId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("delete %{public}s data failed", PRODUCT_INFO_TABLE.c_str());
            return DP_DEL_PRODUCT_INFO_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ProductInfoDao::UpdateProductInfo(const ProductInfo& productInfo)
{
    ValuesBucket values;
    ProductInfoToEntries(productInfo, values);
    int32_t changeRowCnt = CHANGEROWCNT_INIT;
    {
        std::lock_guard<std::mutex> lock(rdbMutex_);
        int32_t ret = ProfileDataRdbAdapter::GetInstance().Update(changeRowCnt, PRODUCT_INFO_TABLE, values,
            PRODUCT_ID + " = ?", std::vector<ValueObject>{ ValueObject(productInfo.GetProductId()) });
        if (ret != DP_SUCCESS) {
            HILOGE("Update %{public}s table failed", PRODUCT_INFO_TABLE.c_str());
            return DP_UPDATE_PRODUCT_INFO_FAIL;
        }
    }
    HILOGI("end!");
    return DP_SUCCESS;
}

int32_t ProductInfoDao::CreateTable()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    int32_t ret = ProfileDataRdbAdapter::GetInstance().CreateTable(CREATE_PRODUCT_INFO_TABLE_SQL);
    if (ret != DP_SUCCESS) {
        HILOGE("%{public}s create failed", PRODUCT_INFO_TABLE.c_str());
        return DP_CREATE_TABLE_FAIL;
    }
    return DP_SUCCESS;
}

int32_t ProductInfoDao::CreateIndex()
{
    return DP_SUCCESS;
}

bool ProductInfoDao::CreateQuerySqlAndCondition(const std::vector<std::string>& productIds,
    std::string& sql, std::vector<ValueObject>& condition)
{
    sql = SELECT_PRODUCT_INFO_TABLE;
    bool flag = false;
    if (!productIds.empty()) {
        sql += PRODUCT_ID + " IN(";
        for (const auto& prodId : productIds) {
            sql += "?,";
            condition.emplace_back(ValueObject(prodId));
        }
        sql.erase(sql.end() - 1);
        sql += ")";
        flag = true;
    }
    return flag;
}

int32_t ProductInfoDao::ProductInfoToEntries(const ProductInfo& productInfo, ValuesBucket& values)
{
    values.PutString(PRODUCT_ID, productInfo.GetProductId());
    values.PutString(DEVICE_MODEL, productInfo.GetModel());
    values.PutString(PRODUCT_NAME, productInfo.GetProductName());
    values.PutString(PRODUCT_SHORT_NAME, productInfo.GetProductShortName());
    values.PutString(IMAGE_VERSION, productInfo.GetImageVersion());
    return DP_SUCCESS;
}

int32_t ProductInfoDao::ConvertToProductInfo(std::shared_ptr<ResultSet> resultSet, ProductInfo& productInfo)
{
    if (resultSet == nullptr) {
        HILOGE("resultSet is nullptr");
        return DP_GET_RESULTSET_FAIL;
    }
    RowEntity rowEntity;
    if (resultSet->GetRow(rowEntity) != DP_SUCCESS) {
        HILOGE("get resultSet failed");
        return DP_GET_RESULTSET_FAIL;
    }
    productInfo.SetProductId(rowEntity.Get(PRODUCT_ID));
    productInfo.SetModel(rowEntity.Get(DEVICE_MODEL));
    productInfo.SetProductName(rowEntity.Get(PRODUCT_NAME));
    productInfo.SetProductShortName(rowEntity.Get(PRODUCT_SHORT_NAME));
    productInfo.SetImageVersion(rowEntity.Get(IMAGE_VERSION));
    return DP_SUCCESS;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS