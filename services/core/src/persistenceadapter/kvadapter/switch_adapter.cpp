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

#include "switch_adapter.h"

#include "distributed_device_profile_errors.h"
#include "distributed_device_profile_log.h"
#include "kv_data_change_listener.h"
#include "types.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(SwitchAdapter);

namespace {
    const std::string TAG = "SwitchAdapter";
}

void SwitchAdapter::Init()
{
    HILOGI("called");
    
    observer_ = std::make_shared<KvDataChangeListener>();
}

void SwitchAdapter::Uninit() {}

int32_t SwitchAdapter::PutSwitch(const std::string& appId, uint32_t value, uint16_t length)
{
    HILOGI("called");
    if (appId.empty()) {
        HILOGE("params are invalid");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::AppId appID;
    appID.appId = appId;
    const DistributedKv::SwitchData switchData = {value, length};
    DistributedKv::Status res = kvDataMgr_.PutSwitch(appID, switchData);
    if (res != DistributedKv::Status::SUCCESS) {
        HILOGE("PutSwitch kv to db failed, ret: %d", res);
        return DP_PUT_KV_DB_FAIL;
    }
    return DP_SUCCESS;
}

int32_t SwitchAdapter::GetSwitch(const std::string& appId, const std::string& networkId, uint32_t& value)
{
    HILOGI("called");
    if (appId.empty() || networkId.empty()) {
        HILOGE("params are invalid");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::AppId appID;
    appID.appId = appId;
    auto res = kvDataMgr_.GetSwitch(appID, networkId);
    if (res.first != DistributedKv::Status::SUCCESS) {
        HILOGE("switch from db failed, ret: %d", res.first);
        return DP_PUT_KV_DB_FAIL;
    }
    HILOGI("switch value %{public}u", res.second.value);
    value = res.second.value;
    return DP_SUCCESS;
}

int32_t SwitchAdapter::SubscribeSwitchData(const std::string& appId)
{
    HILOGI("called");
    if (appId.empty()) {
        HILOGE("appid is empty");
        return DP_INVALID_PARAMS;
    }
    DistributedKv::AppId appID;
    appID.appId = appId;
    auto res = kvDataMgr_.SubscribeSwitchData(appID, observer_);
    if (res != DistributedKv::Status::SUCCESS) {
        HILOGE("SubscribeSwitchData failed, ret: %d", res);
        return DP_SUBSCRIBE_FAILED;
    }
    return DP_SUCCESS;
}

int32_t SwitchAdapter::UnsubscribeSwitchData(const std::string& appId)
{
    HILOGI("called");
    if (appId.empty()) {
        HILOGE("appid is empty");
        return DP_INVALID_PARAMS;
    }

    DistributedKv::AppId appID;
    appID.appId = appId;
    auto res = kvDataMgr_.UnsubscribeSwitchData(appID, observer_);
    if (res != DistributedKv::Status::SUCCESS) {
        HILOGE("UnSubscribeSwitchData failed, ret: %d", res);
        return DP_UNSUBSCRIBE_FAILED;
    }
    return DP_SUCCESS;
}
} // namespace DeviceProfile
} // namespace OHOS
