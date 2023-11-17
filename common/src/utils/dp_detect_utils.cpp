/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <securec.h>
#include "dp_detect_utils.h"

#include "distributed_device_profile_constants.h"
#include "distributed_device_profile_log.h"
#include "distributed_device_profile_errors.h"


namespace OHOS {
namespace DistributedDeviceProfile {
namespace {
    const std::string TAG = "DPDetectUtils";
}
std::mutex operationMtx_;
const char *sessName = "com.huawei.profile-session";
const char *pkgName = "com.huawei.profile";

static int32_t OnSessionOpened(int32_t sessionId, int32_t result)
{
    return 0;
}

static void OnSessionClosed(int32_t sessionId)
{
    return;
}

ISessionListener sessListener_ {.OnSessionOpened = OnSessionOpened,
                                .OnSessionClosed = OnSessionClosed};

int32_t DPDetectVersion::DetectRemoteDPVersion(const std::string& peerDevId)
{
    std::lock_guard<std::mutex> lock(operationMtx_);
    if (peerDevId.empty()) {
        HILOGE("input peerDevId is empty");
        return DP_INVALID_PARAMS;
    }
    int32_t ret = CreateSessionServer(pkgName, sessName, &sessListener_);
    if (ret != DP_SUCCESS) {
        HILOGE("create session adapter failed");
        return DP_CREATE_SESSION_FAILED;
    }
    int dataType = TYPE_BYTES;
    SessionAttribute attribute = { 0 };
    attribute.dataType = dataType;
    attribute.linkTypeNum = LINK_TYPE_MAX;
    LinkType linkTypeList[LINK_TYPE_MAX] = {
        LINK_TYPE_WIFI_P2P,
        LINK_TYPE_WIFI_WLAN_5G,
        LINK_TYPE_WIFI_WLAN_2G,
        LINK_TYPE_BR,
    };
    ret = memcpy_s(attribute.linkType, sizeof(attribute.linkType), linkTypeList, sizeof(linkTypeList));
    if (ret != EOK) {
        HILOGE("data copy failed.");
        return DP_NO_MEMORY;
    }
    int32_t sessionId = OpenSession(sessName, sessName, peerDevId.c_str(), "0", &attribute);
    if (sessionId < 0) {
        HILOGE("open softbus session failed for sessionId:%{pubilc}d", sessionId);
        return DP_SESSION_ERROR;
    }
    CloseSession(sessionId);
    RemoveSessionServer(pkgName, sessName);
    return DP_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS