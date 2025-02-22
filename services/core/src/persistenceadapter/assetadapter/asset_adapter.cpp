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

#include "asset_adapter.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(AssetAdapter);
namespace {
    const std::string TAG = "AssetAdapter";
}

int32_t AssetAdapter::PutAsset(const AssetAttr *attr, uint32_t attrCnt)
{
    int32_t ret = AssetAdd(attr, attrCnt);
    if (ret == SEC_ASSET_DUPLICATED) {
        HILOGE("add duplicated");
        return DP_ASSET_DUPLICATED;
    }
    if (ret != SEC_ASSET_SUCCESS) {
        HILOGE("asset add fail, error code is %{public}d", ret);
        return DP_PUT_ASSET_ERROR;
    }
    return DP_SUCCESS;
}

int32_t AssetAdapter::UpdateAsset(const AssetAttr* query, uint32_t queryCnt,
    const AssetAttr* attrToUpdate, uint32_t updateCnt)
{
    int32_t ret = AssetUpdate(query, queryCnt, attrToUpdate, updateCnt);
    if (ret == SEC_ASSET_NOT_FOUND) {
        HILOGE("not find asset");
        return DP_GET_ASSET_NOT_FIND;
    }
    if (ret != SEC_ASSET_SUCCESS) {
        HILOGE("asset update fail, error code is %{public}d", ret);
        return DP_UPDATE_ASSET_ERROR;
    }
    return DP_SUCCESS;
}

int32_t AssetAdapter::GetAsset(const AssetAttr* query, uint32_t queryCnt, AssetResultSet* resultSet)
{
    int32_t ret = AssetQuery(query, queryCnt, resultSet);
    if (ret == SEC_ASSET_NOT_FOUND) {
        HILOGE("not find asset");
        return DP_GET_ASSET_NOT_FIND;
    }
    if (ret != SEC_ASSET_SUCCESS) {
        HILOGE("asset get fail, error code is %{public}d", ret);
        AssetFreeResultSet(resultSet);
        return DP_GET_ASSET_ERROE;
    }
    return DP_SUCCESS;
}

int32_t AssetAdapter::DeleteAsset(const AssetAttr* query, uint32_t queryCnt)
{
    int32_t ret = AssetRemove(query, queryCnt);
    if (ret != SEC_ASSET_SUCCESS) {
        HILOGE("asset remove fail, error code is %{public}d", ret);
        return DP_DELETE_ASSET_ERROR;
    }
    return DP_SUCCESS;
}

AssetAttr* AssetAdapter::ParseAttr(const AssetResult *result, AssetTag tag)
{
    AssetAttr* aeestResult = AssetParseAttr(result, tag);
    if (aeestResult == nullptr) {
        HILOGE("asset parse fail");
        return nullptr;
    }
    return aeestResult;
}

void AssetAdapter::FreeResultSet(AssetResultSet *resultSet)
{
    AssetFreeResultSet(resultSet);
}

} // namespace DistributedDeviceProfile
} // namespace OHOS
