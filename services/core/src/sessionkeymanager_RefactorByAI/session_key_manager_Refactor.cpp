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

#include "session_key_manager_Refactor.h"
#include "asset_adapter.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include <fstream>
#include <cstring>

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SessionKeyManager);
namespace {
    const std::string TAG = "SessionKeyManager";
    const std::string RANDOM_DEVICE = "/dev/urandom";
}

void SessionKeyManager::SecureClearMemory(void* ptr, size_t size)
{
    if (ptr == nullptr || size == 0) {
        return;
    }
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

bool SessionKeyManager::GenerateSecureRandomNumber(int32_t& randomNumber)
{
    std::ifstream randomFile(RANDOM_DEVICE, std::ios::binary);
    if (!randomFile.is_open()) {
        HILOGE("Failed to open random device");
        return false;
    }
    
    randomFile.read(reinterpret_cast<char*>(&randomNumber), sizeof(randomNumber));
    if (!randomFile) {
        HILOGE("Failed to read from random device");
        return false;
    }
    
    randomNumber = randomNumber < 0 ? -randomNumber : randomNumber;
    return true;
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

    AssetAttr attr[] = {
        { .tag = SEC_ASSET_TAG_ALIAS, .value = aliasValue },
        { .tag = SEC_ASSET_TAG_USER_ID, .value = userIdValue },
        { .tag = SEC_ASSET_TAG_SECRET, .value = secretValue }
    };

    int32_t ret = AssetAdapter::GetInstance().PutAsset(attr, sizeof(attr) / sizeof(attr[0]));
    if (ret != DP_SUCCESS) {
        HILOGE("PutSessionKey failed");
        SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
        SecureClearMemory(secretValue.blob.data, secretValue.blob.size);
        return ret;
    }
    
    SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
    SecureClearMemory(secretValue.blob.data, secretValue.blob.size);
    
    HILOGI("userId : %{public}u, sessionKeyId : %{public}d", userId, sessionKeyId);
    return DP_SUCCESS;
}

int32_t SessionKeyManager::GetSessionKey(uint32_t userId,
    int32_t sessionKeyId, std::vector<uint8_t>& sessionKey)
{
    HILOGI("call! userId : %{public}u, sessionKeyId : %{public}d", userId, sessionKeyId);
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
        SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
        AssetAdapter::GetInstance().FreeResultSet(&resultSet);
        return ret;
    }

    AssetAttr* secret = AssetAdapter::GetInstance().ParseAttr(resultSet.results, SEC_ASSET_TAG_SECRET);
    if (secret == nullptr) {
        HILOGE("ParseAttr failed");
        SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
        AssetAdapter::GetInstance().FreeResultSet(&resultSet);
        return DP_GET_ASSET_ERROE;
    }
    
    uint32_t length = secret->value.blob.size;
    uint8_t* data = secret->value.blob.data;
    if (data == nullptr || length == 0 || length > MAX_SESSIONKEY_SIZE) {
        HILOGE("result invalid");
        SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
        data = nullptr;
        AssetAdapter::GetInstance().FreeResultSet(&resultSet);
        return DP_GET_ASSET_ERROE;
    }
    
    sessionKey = std::vector<uint8_t>(data, data + length);
    
    SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
    AssetAdapter::GetInstance().FreeResultSet(&resultSet);
    
    HILOGI("success!");
    return DP_SUCCESS;
}

int32_t SessionKeyManager::UpdateSessionKey(uint32_t userId,
    int32_t sessionKeyId, const std::vector<uint8_t>& sessionKey)
{
    HILOGI("call! userId : %{public}u, sessionKeyId : %{public}d", userId, sessionKeyId);
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
        SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
        SecureClearMemory(secretValue.blob.data, secretValue.blob.size);
        return ret;
    }
    
    SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
    SecureClearMemory(secretValue.blob.data, secretValue.blob.size);
    
    HILOGI("success!");
    return DP_SUCCESS;
}

int32_t SessionKeyManager::DeleteSessionKey(uint32_t userId, int32_t sessionKeyId)
{
    HILOGI("call! userId : %{public}u, sessionKeyId : %{public}d", userId, sessionKeyId);
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
        SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
        return ret;
    }
    
    SecureClearMemory(aliasValue.blob.data, aliasValue.blob.size);
    HILOGI("success!");
    return DP_SUCCESS;
}

void SessionKeyManager::GeneratedSessionKeyId(uint32_t userId, int32_t& sessionKeyId)
{
    HILOGI("call");
    int32_t ret = 0;
    int32_t randomNumber = 0;
    
    do {
        if (!GenerateSecureRandomNumber(randomNumber)) {
            HILOGE("Failed to generate secure random number, fallback to alternative");
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<int32_t> dis(0, INT32_MAX);
            randomNumber = dis(gen);
        }
        
        std::vector<uint8_t> sessionKey;
        ret = GetSessionKey(userId, randomNumber, sessionKey);
        if (ret == DP_SUCCESS && !sessionKey.empty()) {
            SecureClearMemory(sessionKey.data(), sessionKey.size());
        }
    } while (ret == DP_SUCCESS);
    
    sessionKeyId = randomNumber;
    HILOGI("success! userId : %{public}u, sessionKeyId : %{public}d", userId, sessionKeyId);
    return;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS