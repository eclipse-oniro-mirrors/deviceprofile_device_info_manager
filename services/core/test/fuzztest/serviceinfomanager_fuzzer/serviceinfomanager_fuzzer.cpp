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

void PutServiceInfoProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) * 2 + sizeof(int64_t) * 6 + sizeof(int8_t) + 1)) {
        return;
    }
    ServiceInfoProfileNew profile;
    FuzzedDataProvider fdp(data, size);
    int32_t regServiceIdValue = fdp.ConsumeIntegral<int32_t>();
    profile.SetRegServiceId(regServiceIdValue);
    std::string deviceIdValue = fdp.ConsumeRandomLengthString();
    profile.SetDeviceId(deviceIdValue);
    int32_t userIdValue = fdp.ConsumeIntegral<int32_t>();
    profile.SetUserId(userIdValue);
    int64_t tokenIdValue = fdp.ConsumeIntegral<int64_t>();
    profile.SetTokenId(tokenIdValue);
    int8_t SerPubStateValue = fdp.ConsumeIntegral<int8_t>();
    profile.SetSerPubState(SerPubStateValue);
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

void DeleteServiceInfoProfileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) * 2 + 1)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t regServiceId = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    ServiceInfoProfileManage::GetInstance().DeleteServiceInfoProfile(regServiceId, userId);
}

void GetServiceInfoProfileByServiceIdFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t) * 3 + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t serviceId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    ServiceInfoProfileManage::GetInstance().GetServiceInfoProfileByServiceId(serviceId, profile);
}

void GetServiceInfoProfileByTokenIdFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t) * 3 + 1) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t tokenId = fdp.ConsumeIntegral<int64_t>();
    ServiceInfoProfileNew profile;

    profile.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    profile.SetServiceType(fdp.ConsumeRandomLengthString());
    ServiceInfoProfileManage::GetInstance().GetServiceInfoProfileByTokenId(tokenId, profile);
}

void SetServiceInfoProfileFuzzTest(const uint8_t* data, size_t size)
{
    if (!data || size < sizeof(int64_t) * 7 + sizeof(int32_t) + sizeof(int8_t) + 2) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    
    std::string regServiceId = fdp.ConsumeRandomLengthString();
    std::map<std::string, std::string> finalSerProfile;
    
    std::string prefix = "serviceInfo#" + regServiceId + "#";
    finalSerProfile[prefix + "deviceId"] = fdp.ConsumeRandomLengthString();
    finalSerProfile[prefix + "isMultiUser"] = fdp.ConsumeBool() ? "true" : "false";
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
    OHOS::DistributedDeviceProfile::PutServiceInfoProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::DeleteServiceInfoProfileFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByServiceIdFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::GetServiceInfoProfileByTokenIdFuzzTest(data, size);
    OHOS::DistributedDeviceProfile::SetServiceInfoProfileFuzzTest(data, size);

    return 0;
}
