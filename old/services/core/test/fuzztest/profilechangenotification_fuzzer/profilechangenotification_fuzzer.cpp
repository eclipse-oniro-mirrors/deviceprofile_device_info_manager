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

#include "profilechangenotification_fuzzer.h"

#include "profile_change_notification.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <string>

namespace OHOS {
namespace DeviceProfile {

void GetProfileEntriesFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::shared_ptr<ProfileChangeNotification> profileNotification =
        std::make_shared<ProfileChangeNotification>();
    profileNotification->GetProfileEntries();
}

void GetDeviceIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::shared_ptr<ProfileChangeNotification> profileNotification =
        std::make_shared<ProfileChangeNotification>();
    profileNotification->GetDeviceId();
}

void MarshallingFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    Parcel parcel;
    std::shared_ptr<ProfileChangeNotification> profileNotification =
        std::make_shared<ProfileChangeNotification>();
    profileNotification->Marshalling(parcel);
}

void UnmarshallingFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    Parcel parcel;
    std::shared_ptr<ProfileChangeNotification> profileNotification =
        std::make_shared<ProfileChangeNotification>();
    profileNotification->Unmarshalling(parcel);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DeviceProfile::GetProfileEntriesFuzzTest(data, size);
    OHOS::DeviceProfile::GetDeviceIdFuzzTest(data, size);
    OHOS::DeviceProfile::MarshallingFuzzTest(data, size);
    OHOS::DeviceProfile::UnmarshallingFuzzTest(data, size);
    return 0;
}
