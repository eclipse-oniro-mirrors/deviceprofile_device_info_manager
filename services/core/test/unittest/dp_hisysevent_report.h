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

#ifndef OHOS_DEVICEPROFILE_HISTSEVENT_REPORT_H
#define OHOS_DEVICEPROFILE_HISTSEVENT_REPORT_H

#include "hisysevent.h"

namespace OHOS {
namespace DeviceProfile {
namespace FaultEvent{
    const std::string DEVICE_PROFILE_SYNC_FAILED = "DEVICE_PROFILE_SYNC_FAILED";
}

namespace ErrorType{
    const std::string FAULT_CODE_KEY = "FAULT_CODE";
}    
    const std::string DOMAIN_NAME = std::string(OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE);

class DpHiSysEventReport {
public:
    static int ReportSyncBehavior(const std::string& eventName);
    static int ReportSyncFault(const std::string& faultName, const int32_t code);
};
} // namespace DeviceProfile
} // namespace OHOS

#endif /* OHOS_DEVICEPROFILE_HISTSEVENT_REPORT_H */