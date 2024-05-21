/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_adapter.h"

#include <securec.h>
#include <unistd.h>

#include "softbus_bus_center.h"
#include "softbus_common.h"


namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(SoftbusAdapter);


SoftbusAdapter::SoftbusAdapter()
{

}

SoftbusAdapter::~SoftbusAdapter()
{

}



int32_t SoftbusAdapter::OpenSoftbusSession(const std::string &mySessionName, const std::string &peerSessionName,
    const std::string &peerDevId) const
{
    // DHLOGI("%s: OpenSoftbusSession mysess:%s peersess:%s id:%s.", LOG_TAG, mySessionName.c_str(),
    //     peerSessionName.c_str(), GetAnonyString(peerDevId).c_str());
    int dataType = TYPE_STREAM;
    //int streamType = COMMON_VIDEO_STREAM;
    SessionAttribute attr = { 0 };
    attr.dataType = dataType;
    attr.linkTypeNum = LINK_TYPE_MAX;
    LinkType linkTypeList[LINK_TYPE_MAX] = {
        LINK_TYPE_WIFI_P2P,
        LINK_TYPE_WIFI_WLAN_5G,

        LINK_TYPE_WIFI_WLAN_2G,
        LINK_TYPE_BR,
    };
    int32_t ret = memcpy_s(attr.linkType, sizeof(attr.linkType), linkTypeList, sizeof(linkTypeList));
    if (ret != EOK) {
        //DHLOGE("%s: Data copy failed.", LOG_TAG);
        return 1001;
    }
    int32_t sessionId = OpenSession(mySessionName.c_str(), peerSessionName.c_str(), peerDevId.c_str(), "0", &attr);
    if (sessionId < 0) {
        //DHLOGE("%s: OpenSession failed sessionId: %." PRId32, LOG_TAG, sessionId);
        return 1002;
    }
    
    //DHLOGI("%s: OpenSoftbusSession success sessionId: %." PRId32, LOG_TAG, sessionId);
    return sessionId;
}

int32_t SoftbusAdapter::CloseSoftbusSession(const int32_t sessionId)
{
    //DHLOGI("%s: CloseSoftbusSession, sessid:%" PRId32, LOG_TAG, sessionId);
    CloseSession(sessionId);
    //DHLOGI("%s: CloseSoftbusSession success.", LOG_TAG);
    return 1000;
}

} // namespace DistributedHardware
} // namespace OHOS