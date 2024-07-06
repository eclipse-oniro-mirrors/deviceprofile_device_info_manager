/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "profile_event_handler_factory.h"

#include "device_profile_log.h"
#include "profile_change_handler.h"
#include "profile_sync_handler.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "ProfileEventHandlerFactory";
}

IMPLEMENT_SINGLE_INSTANCE(ProfileEventHandlerFactory);

ProfileEventHandlerFactory::ProfileEventHandlerFactory()
{
    handlersMap_[ProfileEvent::EVENT_SYNC_COMPLETED] =
        &ProfileEventHandlerFactory::GetProfileSyncHandlerInner;
    handlersMap_[ProfileEvent::EVENT_PROFILE_CHANGED] =
        &ProfileEventHandlerFactory::GetProfileChangeHandlerInner;
}

std::shared_ptr<ProfileEventHandler> ProfileEventHandlerFactory::GetHandler(ProfileEvent profileEvent)
{
    HILOGI("get handler for event = %{public}u", static_cast<uint32_t>(profileEvent));
    switch (static_cast<uint32_t>(profileEvent)) {
        case ProfileEvent::EVENT_SYNC_COMPLETED:
            return ProfileEventHandlerFactory::GetProfileSyncHandlerInner();
        case ProfileEvent::EVENT_PROFILE_CHANGED:
            return ProfileEventHandlerFactory::GetProfileChangeHandlerInner();
    }
    return nullptr;
}

std::shared_ptr<ProfileEventHandler> ProfileEventHandlerFactory::GetProfileChangeHandlerInner()
{
    return std::make_shared<ProfileChangeHandler>("profileChange");
}

std::shared_ptr<ProfileEventHandler> ProfileEventHandlerFactory::GetProfileSyncHandlerInner()
{
    return std::make_shared<ProfileSyncHandler>("profileSync");
}
} // namespace DeviceProfile
} // namespace OHOS
