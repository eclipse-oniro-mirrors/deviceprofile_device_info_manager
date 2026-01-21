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

#include "high_risk_interface_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/types.h>
#include "sys/stat.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "iremote_stub.h"

#include "distributed_device_profile_enums.h"
#include "distributed_device_profile_service_new.h"
#include "dp_ipc_interface_code.h"
namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    constexpr size_t THRESHOLD = 10;
    constexpr int32_t OFFSET = 4;
    const std::u16string DP_INTERFACE_TOKEN = u"OHOS.DeviceProfile.IDistributedDeviceProfile";
}

void MockPermission(const char* processName)
{
    static const char *perms[] = {
        "ohos.permission.DISTRIBUTED_DATASYNC"
    };

    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

void HighRiskInterfaceFuzzerTest(const uint8_t* rawData, size_t size)
{
    MockPermission("distributedsched");
    rawData = rawData + OFFSET;
    size = size - OFFSET;
    MessageParcel data;
    data.WriteInterfaceToken(DP_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::string baseDir = "/data/service/el1/public/database/distributed_device_profile_service";
    mkdir(baseDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    std::vector<uint32_t> highRiskInterfaces;
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::PUT_CHAR_PROFILE));
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::PUT_DEVICE_PROFILE_BATCH));
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::GET_SERVICE_PROFILE));
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::GET_DEVICE_PROFILE_NEW));
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::GET_CHAR_PROFILE));
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::PUT_SERVICE_PROFILE));
    highRiskInterfaces.emplace_back(static_cast<uint32_t>(DpIpcInterfaceCode::SYNC_DEVICE_PROFILE_NEW));
    for (uint32_t code : highRiskInterfaces) {
        DistributedDeviceProfileServiceNew::GetInstance().OnRemoteRequest(code, data, reply, option);
        DistributedDeviceProfileServiceNew::GetInstance().NotifyEventInner(code, data, reply, option);
    }
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::DistributedDeviceProfile::THRESHOLD) {
        return 0;
    }
    OHOS::DistributedDeviceProfile::HighRiskInterfaceFuzzerTest(data, size);
    return 0;
}
