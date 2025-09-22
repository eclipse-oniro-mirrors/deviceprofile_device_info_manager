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

#include "profilecontrolutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"
#include "kv_adapter.h"
#include "distributed_kv_data_manager.h"
#include "ikv_adapter.h"

#include "service_info_profile_new.h"
#include "distributed_device_profile_constants.h"
#include "profile_control_utils.h"
#include "listener/kv_data_change_listener.h"
#include "listener/kv_sync_completed_listener.h"
#include "listener/kv_store_death_recipient.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void DeleteServiceInfoProfileFuzzerTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) * 2)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t regServiceId = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<IKVAdapter> kvStore = nullptr;
    std::string appId = fdp.ConsumeRandomLengthString(64);
    std::string storeId = fdp.ConsumeRandomLengthString(64);
    kvStore = std::make_shared<KVAdapter>(appId, storeId,
        std::make_shared<KvDataChangeListener>(storeId),
        std::make_shared<KvSyncCompletedListener>(storeId), std::make_shared<KvDeathRecipient>(storeId),
        DistributedKv::TYPE_DYNAMICAL);

    ProfileControlUtils::DeleteServiceInfoProfile(kvStore, regServiceId, userId);
    kvStore = nullptr;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::DeleteServiceInfoProfileFuzzerTest(data, size);

    return 0;
}
