/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "online_sync_table.h"

#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::DistributedKv;

namespace {
const std::string TAG = "OnlineSyncTable";

const std::string APP_ID = "distributed_device_profile_service";
const std::string STORE_ID = "online_sync_storage";
}

OnlineSyncTable::OnlineSyncTable() : DeviceProfileStorage(APP_ID, STORE_ID)
{
}

void OnlineSyncTable::Init()
{
    HILOGD("called");
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
    };
    SetOptions(options);
    DeviceProfileStorage::Init();
}
} // namespace DeviceProfile
} // namespace OHOS
