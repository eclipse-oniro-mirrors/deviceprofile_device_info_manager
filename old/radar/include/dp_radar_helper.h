/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_RADAR_HELPER_H
#define OHOS_DP_RADAR_HELPER_H

#include <cstdint>
#include <chrono>
#include <string>
#include <map>
#include <list>

#include "single_instance.h"

namespace OHOS {
namespace DeviceProfile {
const std::string ORGPKGNAME = "deviceprofile";
const std::string SAMAGRNAME = "SA";
const std::string kvNAME = "distrubitedKv";
const std::string DP_DATA_OPERATE_BEHAVIOR = "DP_DATA_OPERATE_BEHAVIOR";
const int32_t SUBSYS_DISTRIBUTEDHARDWARE_DP = 205;
constexpr int32_t INVALID_UDID_LENGTH = 10;
constexpr int32_t SUBSTR_UDID_LENGTH = 5;
enum class BizScene : int32_t {
    DP_GET_SA = 0x1,
    DP_ADD_DATA = 0x2,
    DP_DELET_DATA = 0x3,
    DP_GET_DATA = 0x4,
    DP_SUBSCRIBE_DATA = 0x5,
    DP_UNSUBSCRIBE_DATA = 0x6,
    DP_SYNC_DATA = 0x7,
};

enum class StageRes : int32_t {
    STAGE_IDLE = 0x0,
    STAGE_SUCC = 0x1,
    STAGE_FAIL = 0x2,
    STAGE_CANCEL = 0x3,
    STAGE_UNKNOW = 0x4,
};

enum class BizState : int32_t {
    BIZ_STATE_START = 0x1,
    BIZ_STATE_END = 0x2,
    BIZ_STATE_CANCEL = 0x3,
};

enum class GetSaStage : int32_t {
    DP_CHECK_SA = 0x1,
    DP_LOAD_SA = 0x2,
    DP_SA_CHACK_AUTH = 0x3,
};

enum class GetDataStage : int32_t {
    DP_GET_DATA = 0x1,
};

enum class AddDataStage : int32_t {
    DP_ADD_DATA = 0x1,
};

enum class DelDataStage : int32_t {
    DP_DELET_DATA = 0x1,
};

enum class SubscribeDataStage : int32_t {
    DP_SUBSCRIBE_DATA = 0x1,
    DP_RECIVE_DATA_CHANGE = 0x2,
};

enum class UnSubscribeDataStage : int32_t {
    DP_UNSUBSCRIBE_DATA = 0x1,
};

enum class SyncDataStage : int32_t {
    DP_SYNC_DATA = 0x1,
    DP_RECIVE_SYNC_CALLBACK = 0x2,
};

enum class Module : int32_t {
    DEVICE_PROFILE = 0x0,
    SA_MGR = 0x1,
    DISTRIBUTED_KV = 0x2,
};

struct RadarInfo {
    std::string funcName;
    int32_t stageRes;
    int32_t bizState;
    std::string toCallPkg;
    std::string hostName;
    std::string localUdid;
    std::string peerUdid;
    int32_t errCode;
};

class DpRadarHelper {
    DECLARE_SINGLE_INSTANCE(DpRadarHelper);
public:
    bool ReportCheckDpSa(struct RadarInfo info);
    bool ReportLoadDpSa(struct RadarInfo info);
    bool ReportLoadDpSaCb(struct RadarInfo info);
    bool ReportSaCheckAuth(struct RadarInfo info);
    bool ReportGetData(struct RadarInfo info);
    bool ReportAddData(struct RadarInfo info);
    bool ReportDeleteData(struct RadarInfo info);
    bool ReportSubscribeData(struct RadarInfo info);
    bool ReportNotifyDataChange(struct RadarInfo info);
    bool ReportUnsbscribeData(struct RadarInfo info);
    bool ReportSyncData(struct RadarInfo info);
    bool ReportSyncDataCb(struct RadarInfo info);
    std::string GetHostNameByServiceId(std::string serviceId);
    std::string GetStringUdidList(std::list<std::string> &udidList);
private:
    int32_t GetErrorCode(int32_t errCode, int32_t module);
    std::string GetAnonyUdid(std::string udid);
    std::map<std::string, std::string> hostNameMap_ = {
        {"infoCollection", "CollaborationFwk"},
        {"pasteboardService", "pasteboardService"},
        {"appInfo", "dmsfwk"},
        {"deviceStatus", "msdp"},
    };
};
} // namespace DeviceProfile
} // namespace OHOS
#endif // OHOS_DP_RADAR_HELPER_H