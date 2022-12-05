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
#include "dp_device_manager.h"
#include "sync_coordinator.h"

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
    if (jsonObject.find(FIELD_GROUP_NAME) != jsonObject.end()) {
        jsonObject.at(FIELD_GROUP_NAME).get_to(groupInfo.groupName);
    }
    if (jsonObject.find(FIELD_GROUP_ID) != jsonObject.end()) {
        jsonObject.at(FIELD_GROUP_ID).get_to(groupInfo.groupId);
    }
    if (jsonObject.find(FIELD_GROUP_OWNER) != jsonObject.end()) {
        jsonObject.at(FIELD_GROUP_OWNER).get_to(groupInfo.groupOwner);
    }
    if (jsonObject.find(FIELD_GROUP_TYPE) != jsonObject.end()) {
        jsonObject.at(FIELD_GROUP_TYPE).get_to(groupInfo.groupType);
    }
    if (jsonObject.find(FIELD_GROUP_VISIBILITY) != jsonObject.end()) {
        jsonObject.at(FIELD_GROUP_VISIBILITY).get_to(groupInfo.groupVisibility);
    }
}

bool TrustGroupManager::InitHichainService()
{
    if (hichainGmInstance_ != nullptr) {
        return true;
    }

    if (InitDeviceAuthService() != ERR_OK) {
        HILOGE("auth InitDeviceAuthService failed");
        return false;
    }

    hichainGmInstance_ = GetGmInstance();
    if (hichainGmInstance_ == nullptr) {
        HILOGE("auth GetGmInstance failed");
        return false;
    }
    
    InitDataChangeListener();
    HILOGI("init succeeded");
    return true;
}

void TrustGroupManager::InitDataChangeListener()
{
    dataChangeListener_.onDeviceUnBound = OnDeviceUnBoundAdapter;
    if (hichainGmInstance_->regDataChangeListener(AUTH_APPID.c_str(), &dataChangeListener_) != 0) {
        HILOGE("auth RegDataChangeListener failed");
    }
}

bool TrustGroupManager::CheckTrustGroup(const std::string& deviceId)
{
    if (!InitHichainService()) {
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
    return CheckGroupsInfo(returnGroups, groupNum);
}

bool TrustGroupManager::CheckGroupsInfo(const char* returnGroups, uint32_t groupNum)
{
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
        HILOGI("remove unbound deivce profile start, udid = %{public}s",
            DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        if (GetInstance().CheckTrustGroup(udid)) {
            HILOGI("unbound device in trust group");
            return;
        }
        
        if (DeviceProfileStorageManager::GetInstance().RemoveUnBoundDeviceProfile(udid) != ERR_OK) {
            HILOGE("remove unbound device profile failed, udid = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        } else {
            HILOGI("remove unbound deivce profile success, udid = %{public}s",
                DeviceProfileUtils::AnonymizeDeviceId(udid).c_str());
        }
        DpDeviceManager::GetInstance().RemoveDeviceIdsByUdid(udid);
    };
    if (!SyncCoordinator::GetInstance().DispatchSyncTask(removeUnBoundDeviceTask)) {
        HILOGE("post task failed");
        return;
    }
}

bool TrustGroupManager::CheckDeviceId(const std::string udid)
{
    std::string localDeviceId;
    DpDeviceManager::GetInstance().GetLocalDeviceUdid(localDeviceId);
    if (udid.empty() || localDeviceId.empty()) {
        HILOGE("device id is empty");
        return false;
    }

    if (udid == localDeviceId) {
        return false;
    }
    return true;
}
} // namespace DeviceProfile
} // namespace OHOS