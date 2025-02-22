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

#include "session_key_manager.h"
#include "asset_adapter.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SessionKeyManager);
namespace {
    const std::string TAG = "SessionKeyManager";
}

int32_t SessionKeyManager::PutSessionKey(uint32_t userId,
    const std::vector<uint8_t>& sessionKey, int32_t& sessionKeyId)
{
    if (userId == 0 || sessionKey.empty() || sessionKey.size() > MAX_SESSIONKEY_SIZE) {
        HILOGE("params is invalid");
        return DP_INVALID_PARAMS;
    }
    GeneratedSessionKeyId(userId, sessionKeyId);
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(sizeof(sessionKeyId)),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&sessionKeyId)) } };
    AssetValue userIdValue = { .u32 = userId };
    AssetValue secretValue = { .blob = { static_cast<uint32_t>(sessionKey.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sessionKey.data())) } };
    AssetValue accessibilityValue = { .u32 = SEC_ASSET_ACCESSIBILITY_DEVICE_FIRST_UNLOCKED };

    AssetAttr attr[] = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue },
        { .tag = SEC_ASSET_TAG_USER_ID, .value = userIdValue },
        { .tag = SEC_ASSET_TAG_SECRET, .value = secretValue },
        { .tag = SEC_ASSET_TAG_ACCESSIBILITY, .value = accessibilityValue }
    };

    int32_t ret = AssetAdapter::GetInstance().PutAsset(attr, sizeof(attr) / sizeof(attr[0]));
    if (ret != DP_SUCCESS) {
        HILOGE("PutSessionKey failed");
        return ret;
    }
    return DP_SUCCESS;
}

int32_t SessionKeyManager::GetSessionKey(uint32_t userId,
    int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    if (userId == 0) {
        HILOGE("params is invalid");
        return DP_INVALID_PARAMS;
    }
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(sizeof(sessionKeyId)),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&sessionKeyId)) } };
    AssetValue userIdValue = { .u32 = userId };
    AssetValue returnValue = { .u32 = SEC_ASSET_RETURN_ALL };
    AssetAttr attr[] = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue },
        { .tag = SEC_ASSET_TAG_USER_ID, .value = userIdValue },
        { .tag = SEC_ASSET_TAG_RETURN_TYPE, .value = returnValue }
    };

    AssetResultSet resultSet = {0};
    int32_t ret = AssetAdapter::GetInstance().GetAsset(attr, sizeof(attr) / sizeof(attr[0]), &resultSet);
    if (ret != DP_SUCCESS) {
        HILOGE("GetAsset failed");
        AssetAdapter::GetInstance().FreeResultSet(&resultSet);
        return ret;
    }

    AssetAttr* secret = AssetAdapter::GetInstance().ParseAttr(resultSet.results, SEC_ASSET_TAG_SECRET);
    if (secret == nullptr) {
        HILOGE("ParseAttr failed");
        AssetAdapter::GetInstance().FreeResultSet(&resultSet);
        return DP_GET_ASSET_ERROE;
    }
    uint32_t length = secret->value.blob.size;
    uint8_t* data = secret->value.blob.data;
    if (data == nullptr || length == 0 || length > MAX_SESSIONKEY_SIZE) {
        HILOGE("result invalid");
        data = nullptr;
        AssetAdapter::GetInstance().FreeResultSet(&resultSet);
        return DP_GET_ASSET_ERROE;
    }
    sessionKey = std::vector<uint8_t>(data, data + length);
    AssetAdapter::GetInstance().FreeResultSet(&resultSet);
    return DP_SUCCESS;
}

int32_t SessionKeyManager::UpdateSessionKey(uint32_t userId,
    int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    if (userId == 0) {
        HILOGE("params is invalid");
        return DP_INVALID_PARAMS;
    }
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(sizeof(sessionKeyId)),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&sessionKeyId)) } };
    AssetValue userIdValue = { .u32 = userId };
    AssetValue secretValue = { .blob = { static_cast<uint32_t>(sessionKey.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(sessionKey.data())) } };

    AssetAttr attrQuery[] = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue },
        { .tag = SEC_ASSET_TAG_USER_ID, .value = userIdValue }
    };
    AssetAttr attrUpdate[] = {
        { .tag = SEC_ASSET_TAG_SECRET, .value = secretValue }
    };

    int32_t ret = AssetAdapter::GetInstance().UpdateAsset(attrQuery, sizeof(attrQuery) / sizeof(attrQuery[0]),
        attrUpdate, sizeof(attrUpdate) / sizeof(attrUpdate[0]));
    if (ret != DP_SUCCESS) {
        HILOGE("UpdateSessionKey failed");
        return ret;
    }
    return DP_SUCCESS;
}

int32_t SessionKeyManager::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    if (userId == 0) {
        HILOGE("params is invalid");
        return DP_INVALID_PARAMS;
    }
    AssetValue aliasValue = { .blob = { static_cast<uint32_t>(sizeof(sessionKeyId)),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(&sessionKeyId)) } };
    AssetValue userIdValue = { .u32 = userId };
    AssetAttr attr[] = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue },
        { .tag = SEC_ASSET_TAG_USER_ID, .value = userIdValue }
    };

    int32_t ret = AssetAdapter::GetInstance().DeleteAsset(attr, sizeof(attr) / sizeof(attr[0]));
    if (ret != DP_SUCCESS) {
        HILOGE("DeleteAsset failed");
        return ret;
    }
    return DP_SUCCESS;
}

void SessionKeyManager::GeneratedSessionKeyId(uint32_t userId, int32_t& sessionKeyId)
{
    int32_t ret = 0;
    int32_t randomNumber = 0;
    do {
        int32_t seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::default_random_engine generator(seed);
        std::uniform_int_distribution<int32_t> distribution(0, INT32_MAX);
        randomNumber = distribution(generator);
        std::vector<uint8_t> sessionKey;
        ret = GetSessionKey(userId, randomNumber, sessionKey);
    } while (ret == DP_SUCCESS);
    sessionKeyId = randomNumber;
    return;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS
