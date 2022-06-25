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

#include "dfx/dp_hisysevent_report.h"

namespace OHOS {
namespace DeviceProfile {
using namespace OHOS::HiviewDFX;
namespace {
    const std::string TAG = "DpHiSysEventReport";
}

int DpHiSysEventReport::ReportSyncBehavior(const std::string& eventName)
{
    int ret = HiSysEvent::Write(DOMAIN_NAME, eventName, HiSysEvent::EventType::BEHAVIOR);
    return ret;
}

int DpHiSysEventReport::ReportSyncFault(const std::string& faultName, const int32_t code)
{
    int ret = HiSysEvent::Write(DOMAIN_NAME, faultName, HiSysEvent::EventType::FAULT, FAULT_CODE_KEY, code);
    return ret;
}
}
}