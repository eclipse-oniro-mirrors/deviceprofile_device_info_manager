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

#ifndef OHOS_DEVICE_PROFILE_PROFILE_EVENT_HANDLER_FACTORY_H
#define OHOS_DEVICE_PROFILE_PROFILE_EVENT_HANDLER_FACTORY_H

#include "profile_event.h"
#include "profile_event_handler.h"
#include "single_instance.h"

namespace OHOS {
namespace DeviceProfile {
class ProfileEventHandlerFactory {
    DECLARE_SINGLE_INSTANCE_BASE(ProfileEventHandlerFactory);

public:
    ProfileEventHandlerFactory();
    ~ProfileEventHandlerFactory() = default;

    std::shared_ptr<ProfileEventHandler> GetHandler(ProfileEvent profileEvent);

private:
    using Handler = std::shared_ptr<ProfileEventHandler>(ProfileEventHandlerFactory::*)();

    std::shared_ptr<ProfileEventHandler> GetProfileChangeHandlerInner();
    std::shared_ptr<ProfileEventHandler> GetProfileSyncHandlerInner();

private:
    std::map<ProfileEvent, Handler> handlersMap_;
};
}  // namespace DeviceProfile
}  // namespace OHOS
#endif  // OHOS_DEVICE_PROFILE_PROFILE_EVENT_HANDLER_FACTORY_H
