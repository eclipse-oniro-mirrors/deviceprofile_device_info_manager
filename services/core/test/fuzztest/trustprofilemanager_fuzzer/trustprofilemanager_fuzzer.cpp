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

#include "trustprofilemanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "trust_profile_manager.h"
#include "accesser.h"
#include "accessee.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void GetAccessControlProfileByTokenIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }
    int64_t tokenId = *(reinterpret_cast<const int64_t*>(data));
    std::string trustDeviceId(reinterpret_cast<const char*>(data), size);
    int32_t status = *(reinterpret_cast<const int32_t*>(data));
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfileByTokenId(tokenId, trustDeviceId, status, profile);
}

void GetAccessControlProfileOneFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string accountId(reinterpret_cast<const char*>(data), size);
    int32_t userId = *(reinterpret_cast<const int32_t*>(data));
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(userId, accountId, profile);
}

void GetAccessControlProfileTwoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t userId = *(reinterpret_cast<const int32_t*>(data));
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(userId, profile);
}

void GetAllAccessControlProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAllAccessControlProfile(profile);
}

void GetAccessControlProfileThreeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    int32_t bindType = *(reinterpret_cast<const int32_t*>(data));
    int32_t status = *(reinterpret_cast<const int32_t*>(data));
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(bundleName, bindType, status, profile);
}

void GetAccessControlProfileFourFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string trustDeviceId(reinterpret_cast<const char*>(data), size);
    int32_t status = *(reinterpret_cast<const int32_t*>(data));
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(bundleName, trustDeviceId, status, profile);
}

void GetAccessControlProfileFiveFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::map<std::string, std::string> params;
    std::vector<AccessControlProfile> profile;
    AccessControlProfile acProfile;
    profile.push_back(acProfile);
    TrustProfileManager::GetInstance().GetAccessControlProfile(params, profile);
}

void DeleteTrustDeviceProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    TrustProfileManager::GetInstance().DeleteTrustDeviceProfile(deviceId);
}

void DeleteAccessControlProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t ))) {
        return;
    }
    int64_t  status = *(reinterpret_cast<const int64_t *>(data));
    TrustProfileManager::GetInstance().DeleteAccessControlProfile(status);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::GetAccessControlProfileByTokenIdFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetAccessControlProfileOneFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetAccessControlProfileTwoFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetAllAccessControlProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetAccessControlProfileThreeFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetAccessControlProfileFourFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetAccessControlProfileFiveFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DeleteTrustDeviceProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DeleteAccessControlProfileFuzzTest(data, size);
    return 0;
}
