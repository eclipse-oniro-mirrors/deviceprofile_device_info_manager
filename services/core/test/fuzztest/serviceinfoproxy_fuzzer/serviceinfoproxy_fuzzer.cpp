/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#include "serviceinfoproxy_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"

#include "distributed_device_profile_proxy.h"
#include "service_info.h"
#include "user_info.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void ServiceInfoProxyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    sptr<IRemoteObject> remote = nullptr;
    DistributedDeviceProfileProxy proxy(remote);

    ServiceInfo serviceInfo;
    serviceInfo.SetUdid(fdp.ConsumeRandomLengthString());
    serviceInfo.SetUserId(fdp.ConsumeIntegral<int32_t>());
    serviceInfo.SetServiceId(fdp.ConsumeIntegral<int64_t>());
    serviceInfo.SetServiceName(fdp.ConsumeRandomLengthString());

    UserInfo userInfo;
    userInfo.udid = fdp.ConsumeRandomLengthString();
    userInfo.userId = fdp.ConsumeIntegral<int32_t>();
    userInfo.serviceId = fdp.ConsumeIntegral<int64_t>();

    std::vector<ServiceInfo> serviceInfos;
    int32_t saId = fdp.ConsumeIntegral<int32_t>();

    proxy.PutServiceInfo(serviceInfo);
    proxy.DeleteServiceInfo(userInfo);
    proxy.GetAllServiceInfoList(serviceInfos);
    proxy.GetServiceInfosByUserInfo(userInfo, serviceInfos);
    proxy.SubscribeAllServiceInfo(saId, nullptr);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::ServiceInfoProxyFuzzTest(data, size);
    return 0;
}
