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

#include "businesseventmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <sys/types.h>
#include "sys/stat.h"

#include "business_event_manager.h"
#include "business_event.h"

namespace OHOS {
namespace DistributedDeviceProfile {

void PutBusinessEventFuzzTest(FuzzedDataProvider& fdp)
{
    std::string businessKey = fdp.ConsumeRandomLengthString();
    std::string businessValue = fdp.ConsumeRandomLengthString();
    if (businessKey.empty() || businessValue.empty() || businessKey.size() > MAX_STRING_LEN ||
        businessValue.size() > MAX_STRING_LEN) {
        return;
    }

    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey(businessKey);
    businessEvent.SetBusinessValue(businessValue);

    BusinessEventManager::GetInstance().PutBusinessEvent(businessEvent);
}

void GetBusinessEventFuzzTest(FuzzedDataProvider& fdp)
{
    std::string businessKey = fdp.ConsumeRandomLengthString();
    if (businessKey.empty() || businessKey.size() > MAX_STRING_LEN) {
        return;
    }

    BusinessEvent businessEvent;
    businessEvent.SetBusinessKey(businessKey);
    BusinessEventManager::GetInstance().GetBusinessEvent(businessEvent);
}

void BusinessEventManagerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    
    PutBusinessEventFuzzTest(fdp);
    GetBusinessEventFuzzTest(fdp);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedDeviceProfile::BusinessEventManagerFuzzTest(data, size);
    return 0;
}
