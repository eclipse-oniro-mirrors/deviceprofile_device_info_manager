/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "product_info_dao_Refactor.h"

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
    // [原则7] 限制IN条件最大元素数，防止构造超大SQL导致资源耗尽
    constexpr uint32_t MAX_IN_QUERY_SIZE = 500;

    // [原则12] RAII守卫，保证结果集在任何退出路径都被关闭，避免资源泄漏
    class ResultSetGuard {
    public:
        explicit ResultSetGuard(std::shared_ptr<ResultSet> resultSet) : resultSet_(std::move(resultSet)) {}
        ~ResultSetGuard()
        {
            if (resultSet_ != nullptr) {
                resultSet_->Close();
            }
        }
        ResultSetGuard(const ResultSetGuard&) = delete;
        ResultSetGuard& operator=(const ResultSetGuard&) = delete;
    private:
        std::shared_ptr<ResultSet> resultSet_;
    };
}

int32_t ProductInfoDao::Init()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    int32_t ret = RET_INIT;
    if (!ProfileDataRdbAdapter::GetInstance().IsInit()) {
        ret = ProfileDataRdbAdapter::GetInstance().Init();
        if (ret != DP_SUCCESS) {
            HILOGE("ProfileDataRdbAdapter Init failed");
            return DP_INIT_DB_FAILED;
        }
    }
    // [原则12] 校验建表返回值，失败时提前返回，避免数据库处于不一致状态
    ret = CreateTable();
    if (ret != DP_SUCCESS) {
        HILOGE("CreateTable failed, ret:%{public}d", ret);
        return ret;
    }
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
    // [原则3] 校验入库数据合法性，主键字段（productId）不可为空或超长
    if (!IsValidProductInfo(productInfo)) {
        HILOGE("invalid productInfo params");
        return DP_INVALID_PARAMS;
    }
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
    // [原则12] 使用RAII守卫，确保结果集在任何路径下（包括提前返回）都被正确关闭
    ResultSetGuard guard(resultSet);
    int32_t rowCount = ROWCOUNT_INIT;
    resultSet->GetRowCount(rowCount);
    if (rowCount == 0) {
        return DP_NOT_FIND_DATA;
    }
    while (resultSet->GoToNextRow() == DP_SUCCESS) {
        ProductInfo productInfo;
        ConvertToProductInfo(resultSet, productInfo);
        productInfos.emplace_back(productInfo);
    }
    if (productInfos.empty()) {
        return DP_NOT_FIND_DATA;
    }
    return DP_SUCCESS;
}

int32_t ProductInfoDao::DeleteProductInfo(const ProductInfo& productInfo)
{
    // [原则3] 校验productId合法性，防止空主键导致误删或无效操作
    if (productInfo.GetProductId().empty() || productInfo.GetProductId().size() > MAX_STRING_LEN) {
        HILOGE("invalid productId for delete");
        return DP_INVALID_PARAMS;
    }
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
    return DP_SUCCESS;
}

int32_t ProductInfoDao::UpdateProductInfo(const ProductInfo& productInfo)
{
    // [原则3] 校验数据合法性，主键字段（productId）不可为空或超长
    if (!IsValidProductInfo(productInfo)) {
        HILOGE("invalid productInfo params");
        return DP_INVALID_PARAMS;
    }
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
    return DP_SUCCESS;
}

int32_t ProductInfoDao::CreateTable()
{
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
    // [原则7] 限制IN条件元素数量，防止超大SQL导致资源耗尽或超出SQLite占位符上限（默认999）
    if (productIds.size() > MAX_IN_QUERY_SIZE) {
        HILOGE("productIds size too large:%{public}zu", productIds.size());
        return false;
    }
    if (!productIds.empty()) {
        sql += PRODUCT_ID + " IN(";
        for (const auto& prodId : productIds) {
            sql += "?,";
            condition.emplace_back(ValueObject(prodId));
        }
        sql.erase(sql.end() - 1, sql.end());
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

// [原则3] 校验ProductInfo的合法性：主键字段（productId）必填，各字段不超长
bool ProductInfoDao::IsValidProductInfo(const ProductInfo& productInfo) const
{
    if (productInfo.GetProductId().empty() || productInfo.GetProductId().size() > MAX_STRING_LEN) {
        HILOGE("productId is invalid");
        return false;
    }
    if (productInfo.GetModel().size() > MAX_STRING_LEN) {
        HILOGE("model exceeds max length");
        return false;
    }
    if (productInfo.GetProductName().size() > MAX_STRING_LEN) {
        HILOGE("productName exceeds max length");
        return false;
    }
    if (productInfo.GetProductShortName().size() > MAX_STRING_LEN) {
        HILOGE("productShortName exceeds max length");
        return false;
    }
    if (productInfo.GetImageVersion().size() > MAX_STRING_LEN) {
        HILOGE("imageVersion exceeds max length");
        return false;
    }
    return true;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
