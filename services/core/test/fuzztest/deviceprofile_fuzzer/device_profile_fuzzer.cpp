/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "device_profile_fuzzer.h"

#include "iremote_stub.h"
#include "distributed_device_profile_service.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>

namespace OHOS {
namespace DeviceProfile {
namespace {
    constexpr size_t THRESHOLD = 10;
    constexpr uint8_t MAX_CALL_TRANSACTION = 6;
    constexpr int32_t OFFSET = 4;
    int32_t ZERO_BIT = 0;
    int32_t FIRST_BIT = 1;
    int32_t SECOND_BIT = 2;
    int32_t THIRD_BIT = 3;
    int32_t ZERO_MOVE_LEN = 24;
    int32_t FIRST_MOVE_LEN = 16;
    int32_t SECOND_MOVE_LEN = 8;
    const std::u16string DP_INTERFACE_TOKEN = u"OHOS.DeviceProfile.IDistributedDeviceProfile";
}

uint32_t Convert2Uint32(const uint8_t* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    return (ptr[ZERO_BIT] << ZERO_MOVE_LEN) | (ptr[FIRST_BIT] << FIRST_MOVE_LEN) |
        (ptr[SECOND_BIT] << SECOND_MOVE_LEN) | (ptr[THIRD_BIT]);
}

void FuzzDeviceProfile(const uint8_t* rawData, size_t size)
{
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;
    MessageParcel data;
    data.WriteInterfaceToken(DP_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    DistributedDeviceProfileService::GetInstance().OnRemoteRequest(code % MAX_CALL_TRANSACTION, data, reply, option);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::DeviceProfile::THRESHOLD) {
        return 0;
    }

    OHOS::DeviceProfile::FuzzDeviceProfile(data, size);
    return 0;
}

