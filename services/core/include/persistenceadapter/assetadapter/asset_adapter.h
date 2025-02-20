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

#ifndef OHOS_DP_ASSET_ADAPTER_H
#define OHOS_DP_ASSET_ADAPTER_H


#include <string>
#include "asset_system_api.h"
#include "asset_system_type.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class AssetAdapter {
    DECLARE_SINGLE_INSTANCE(AssetAdapter);
public:
    int32_t PutAsset(const AssetAttr* attr, uint32_t attrCnt);
    int32_t UpdateAsset(const AssetAttr* query, uint32_t queryCnt, const AssetAttr* attrToUpdate, uint32_t updateCnt);
    int32_t GetAsset(const AssetAttr* query, uint32_t queryCnt, AssetResultSet* resultSet);
    int32_t DeleteAsset(const AssetAttr* query, uint32_t queryCnt);
    AssetAttr* ParseAttr(const AssetResult* result, AssetTag tag);
    void FreeResultSet(AssetResultSet* resultSet);
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_ASSET_ADAPTER_H
