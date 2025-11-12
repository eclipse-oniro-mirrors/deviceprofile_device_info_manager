/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "trustprofilemanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "trust_profile_manager.h"
#include "accesser.h"
#include "accessee.h"

namespace OHOS {
namespace DistributedDeviceProfile {
void TrustProfileManagerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string trustDeviceId = fdp.ConsumeRandomLengthString();
    std::string accountId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();

    int32_t status = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    int32_t bindType = fdp.ConsumeIntegral<int32_t>();

    int64_t tokenId = fdp.ConsumeIntegral<int64_t>();
    int64_t accessControlId = fdp.ConsumeIntegral<int64_t>();

    std::vector<AccessControlProfile> outProfile;

    TrustProfileManager::GetInstance().GetAccessControlProfileByTokenId(tokenId, trustDeviceId, status, outProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(userId, accountId, outProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(userId, outProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(bundleName, bindType, status, outProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(bundleName, trustDeviceId, status, outProfile);
    TrustProfileManager::GetInstance().DeleteTrustDeviceProfile(deviceId);
    TrustProfileManager::GetInstance().DeleteAccessControlProfile(accessControlId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::TrustProfileManagerFuzzTest(data, size);
    return 0;
}
