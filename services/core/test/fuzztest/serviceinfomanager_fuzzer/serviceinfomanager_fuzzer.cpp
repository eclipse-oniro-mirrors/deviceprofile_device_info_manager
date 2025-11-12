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

#include "serviceinfomanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "service_info_manager.h"
#include "distributed_device_profile_constants.h"
#include "ipc_skeleton.h"
#include "service_info_profile_new.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void PutServiceInfoProfileFuzzTest(FuzzedDataProvider &fdp)
{
    ServiceInfoProfileNew profile;
    int32_t regServiceIdValue = fdp.ConsumeIntegral<int32_t>();
    profile.SetRegServiceId(regServiceIdValue);
    std::string deviceIdValue = fdp.ConsumeRandomLengthString();
    profile.SetDeviceId(deviceIdValue);
    int32_t userIdValue = fdp.ConsumeIntegral<int32_t>();
    profile.SetUserId(userIdValue);
    int64_t tokenIdValue = fdp.ConsumeIntegral<int64_t>();
    profile.SetTokenId(tokenIdValue);
    int8_t serPubStateValue = fdp.ConsumeIntegral<int8_t>();
    profile.SetSerPubState(serPubStateValue);
    int64_t serviceIdValue = fdp.ConsumeIntegral<int64_t>();
    profile.SetServiceId(serviceIdValue);
    std::string serviceTypeValue = fdp.ConsumeRandomLengthString();
    profile.SetServiceType(serviceTypeValue);
    std::string serviceNameValue = fdp.ConsumeRandomLengthString();
    profile.SetServiceName(serviceNameValue);
    std::string serviceDisplayNameValue = fdp.ConsumeRandomLengthString();
    profile.SetServiceDisplayName(serviceDisplayNameValue);

    ServiceInfoProfileManage::GetInstance().PutServiceInfoProfile(profile);
}

void DeleteServiceInfoProfileFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t regServiceId = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    ServiceInfoProfileManage::GetInstance().DeleteServiceInfoProfile(regServiceId, userId);
}

void GetServiceInfoProfileByServiceIdFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t serviceId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    ServiceInfoProfileManage::GetInstance().GetServiceInfoProfileByServiceId(serviceId, profile);
}

void GetServiceInfoProfileByTokenIdFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t tokenId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    std::vector<ServiceInfoProfileNew> profiles {profile};
    ServiceInfoProfileManage::GetInstance().GetServiceInfoProfileByTokenId(tokenId, profiles);
}

void SetServiceInfoProfileFuzzTest(FuzzedDataProvider &fdp)
{
    std::string regServiceId = std::to_string(fdp.ConsumeIntegral<int32_t>());
    std::map<std::string, std::string> finalSerProfile;

    std::string prefix = "serviceInfo#" + regServiceId + "#";
    finalSerProfile[prefix + "deviceId"] = fdp.ConsumeRandomLengthString();
    finalSerProfile[prefix + "publishState"] = std::to_string(fdp.ConsumeIntegral<int8_t>());
    finalSerProfile[prefix + "serviceDisplayName"] = fdp.ConsumeRandomLengthString();
    finalSerProfile[prefix + "serviceId"] = std::to_string(fdp.ConsumeIntegral<int64_t>());
    finalSerProfile[prefix + "serviceName"] = fdp.ConsumeRandomLengthString();
    finalSerProfile[prefix + "serviceType"] = fdp.ConsumeRandomLengthString();
    finalSerProfile[prefix + "tokenId"] = std::to_string(fdp.ConsumeIntegral<int64_t>());
    finalSerProfile[prefix + "userId"] = std::to_string(fdp.ConsumeIntegral<int32_t>());

    ServiceInfoProfileNew profile;
    ServiceInfoProfileManage manager;
    manager.SetServiceInfoProfile(regServiceId, finalSerProfile, profile);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    int32_t minDataSize = sizeof(int64_t) * 2;
    if (!data || size < minDataSize) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::DistributedDeviceProfile::PutServiceInfoProfileFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::DeleteServiceInfoProfileFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByServiceIdFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByTokenIdFuzzTest(fdp);
    OHOS::DistributedDeviceProfile::SetServiceInfoProfileFuzzTest(fdp);

    return 0;
}
