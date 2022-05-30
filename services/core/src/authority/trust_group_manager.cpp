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

#include "trust_group_manager.h"

#include "device_profile_errors.h"
#include "device_profile_log.h"
#include "device_profile_storage_manager.h"
#include "device_profile_utils.h"
#include "device_manager.h"

namespace OHOS {
namespace DeviceProfile {
namespace {
const std::string TAG = "TrustGroupManager";

constexpr int32_t VISIBILITY_PUBLIC = -1;
const std::string AUTH_APPID = "device_profile_auth";
}

IMPLEMENT_SINGLE_INSTANCE(TrustGroupManager);

void from_json(const nlohmann::json& jsonObject, GroupInfo& groupInfo)
{
    jsonObject.at(FIELD_GROUP_NAME).get_to(groupInfo.groupName);
    jsonObject.at(FIELD_GROUP_ID).get_to(groupInfo.groupId);
    jsonObject.at(FIELD_GROUP_OWNER).get_to(groupInfo.groupOwner);
    jsonObject.at(FIELD_GROUP_TYPE).get_to(groupInfo.groupType);
    jsonObject.at(FIELD_GROUP_VISIBILITY).get_to(groupInfo.groupVisibility);
}

std::shared_ptr<AppExecFwk::EventHandler> TrustGroupManager::trustGroupMgrHandler_;

void TrustGroupManager::Init()
{
    if (InitDeviceAuthService() != ERR_OK) {
        HILOGE("auth InitDeviceAuthService failed");
        return;
    }

    hichainGmInstance_ = GetGmInstance();
    if (hichainGmInstance_ == nullptr) {
        HILOGE("auth GetGmInstance failed");
        return;
    }

    InitDataChangeListener();
    if(hichainGmInstance_->regDataChangeListener(AUTH_APPID.c_str(), &dataChangeListener_) != 0){
        HILOGE("auth RegDataChangeListener failed");
        return;
    }
    auto runner = AppExecFwk::EventRunner::Create("trustGroupMgr");
    trustGroupMgrHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    HILOGI("init succeeded");
}

void TrustGroupManager::InitDataChangeListener()
{
    dataChangeListener_.onDeviceUnBound = OnDeviceUnBoundAdapter;
}

bool TrustGroupManager::CheckTrustGroup(const std::string& deviceId)
{
    if (hichainGmInstance_ == nullptr) {
        Init();
    }

    if (hichainGmInstance_ == nullptr) {
        HILOGE("auth GetGmInstance failed");
        return false;
    }

    uint32_t groupNum = 0;
    char* returnGroups = nullptr;
    int32_t ret = hichainGmInstance_->getRelatedGroups(ANY_OS_ACCOUNT, AUTH_APPID.c_str(), deviceId.c_str(),
        &returnGroups, &groupNum);
    if (ret != ERR_OK) {
        HILOGE("failed, ret:%{public}d", ret);
        return false;
    }

    if (returnGroups == nullptr || groupNum == 0) {
        HILOGE("failed, returnGroups is nullptr");
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(returnGroups, nullptr, false);
    if (jsonObject.is_discarded()) {
        HILOGE("returnGroups parse error");
        return false;
    }

    std::vector<GroupInfo> groupInfos = jsonObject.get<std::vector<GroupInfo>>();
    if (groupInfos.empty()) {
        HILOGE("failed, groupInfos is empty");
        return false;
    }
    for (const auto& groupInfo : groupInfos) {
        // check group visibility is whether public or not
        if (groupInfo.groupVisibility != VISIBILITY_PUBLIC) {
            continue;
        }

        // check group type is whether (same count or point to point) or not
        if (groupInfo.groupType == GroupType::IDENTICAL_ACCOUNT_GROUP
                || groupInfo.groupType == GroupType::PEER_TO_PEER_GROUP) {
            HILOGI("check success type = %{public}d", groupInfo.groupType);
            return true;
        }
    }
    HILOGE("check failed, not in trust group");
    return false;
}

void TrustGroupManager::OnDeviceUnBoundAdapter(const char* peerUdid, const char* groupInfo)
{
    const std::string udid = peerUdid;
    if (!CheckDeviceId(udid)) {
        return;
    }

    auto removeUnBoundDeviceTask = [udid = std::move(udid)]() {
        HILOGI("remove unbound deivce profile task start, udid = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        
        if(DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile(udid) != ERR_OK){
            HILOGE("remove unbound device profile task failed, udid = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        } else {
            HILOGI("remove unbound deivce profile task success, udid = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        }
        DeviceManager::GetInstance().RemoveDeviceIdsByUdid(udid);
    };

    if (!trustGroupMgrHandler_->PostTask(removeUnBoundDeviceTask)) {
        HILOGE("post task failed");
        return;
    }
}

bool TrustGroupManager::CheckDeviceId(const std::string udid)
{
    std::string localDeviceId;
    DeviceManager::GetInstance().GetLocalDeviceUdid(localDeviceId);
    if (udid.empty() || localDeviceId.empty()) {
        HILOGE("device id is empty");
        return false;
    }

    if (udid == localDeviceId) {
        HILOGI("device id is local device, not remove device profile, device udid = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        return false;
    }
    return true;
}

} // namespace DeviceProfile
} // namespace OHOS