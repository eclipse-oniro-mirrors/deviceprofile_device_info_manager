/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DEVICE_PROFILE_SUBSCRIBE_INFO_CHECKER_H
#define OHOS_DEVICE_PROFILE_SUBSCRIBE_INFO_CHECKER_H

#include <list>

#include "single_instance.h"
#include "subscribe_info.h"

namespace OHOS {
namespace DeviceProfile {
class SubscribeInfoChecker {
    DECLARE_SINGLE_INSTANCE_BASE(SubscribeInfoChecker);
public:
    SubscribeInfoChecker();
    ~SubscribeInfoChecker() = default;

    bool Check(const std::list<SubscribeInfo>& subscribeInfos);

private:
    using Checker = bool(SubscribeInfoChecker::*)(const SubscribeInfo&);

    bool CheckSyncEventInner(const SubscribeInfo& subscribeInfo);
    bool CheckProfileChangeInner(const SubscribeInfo& subscribeInfo);

private:
    std::map<ProfileEvent, Checker> checkersMap_;
};
}  // namespace DeviceProfile
}  // namespace OHOS

#endif  // OHOS_DEVICE_PROFILE_SUBSCRIBE_INFO_CHECKER_H
