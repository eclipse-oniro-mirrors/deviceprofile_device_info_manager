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

#include "service_info_kv_adapter_test_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>
#include "service_info_kv_adapter.h"

namespace OHOS {
namespace DistributedDeviceProfile {
{
    const int32_t MIN_SIZE = 8;
}

void PutFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string key = fdp.ConsumeRandomLengthString();
    std::string value = fdp.ConsumeRandomLengthString();
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient = nullptr;
    auto adapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
    adapter->Init();
    adapter->Put(key, value);
}

void GetFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string key = fdp.ConsumeRandomLengthString();
    std::string value;
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient = nullptr;
    auto adapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
    adapter->Init();
    adapter->Get(key, value);
}

void DeleteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string key = fdp.ConsumeRandomLengthString();
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient = nullptr;
    auto adapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
    adapter->Init();
    adapter->Delete(key);
}

void PutBatchFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t maxCount = 10;
    if (data == nullptr || size < sizeof(int32_t) + maxCount * MIN_SIZE * 2 + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::map<std::string, std::string> values;
    int32_t count = fdp.ConsumeIntegralInRange<int32_t>(1, maxCount);
    for (int32_t i = 0; i < count; ++i) {
        values[fdp.ConsumeRandomLengthString()] = fdp.ConsumeRandomLengthString();
    }
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient = nullptr;
    auto adapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
    adapter->Init();
    adapter->PutBatch(values);
}

void DeleteBatchFuzzTest(const uint8_t* data, size_t size)
{
    const int32_t maxCount = 10;
    if (data == nullptr || size < sizeof(int32_t) + maxCount * MIN_SIZE * 2 + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> keys;
    int32_t count = fdp.ConsumeIntegralInRange<int32_t>(1, maxCount);
    for (int32_t i = 0; i < count; ++i) {
        keys.push_back(fdp.ConsumeRandomLengthString());
    }
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient = nullptr;
    auto adapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
    adapter->Init();
    adapter->DeleteBatch(keys);
}

void GetByPrefixFuzzTest(const uint8_t* data, size_t size)
{
    constexpr size_t minRequiredSize = 64; 
    if (data == nullptr || size < minRequiredSize) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    std::string keyPrefix = fdp.ConsumeRandomLengthString(minRequiredSize);
    std::map<std::string, std::string> values;

    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> deathRecipient = nullptr;
    auto adapter = std::make_shared<ServiceInfoKvAdapter>(deathRecipient, DistributedKv::TYPE_DYNAMICAL);
    adapter->Init();

    adapter->GetByPrefix(keyPrefix, values);
}
} 
} 

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::PutFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DeleteFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::PutBatchFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DeleteBatchFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetByPrefixFuzzTest(data, size);
    return 0;
}