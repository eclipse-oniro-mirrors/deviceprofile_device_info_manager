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
#include "access_control_profile.h"
#include "characteristic_profile.h"
#include "device_profile.h"
#include "dp_subscribe_info.h"
#include "service_profile.h"
#include "trust_device_profile.h"

namespace OHOS {
namespace DistributedDeviceProfile {
const std::string ORGPKG_NAME = "deviceprofile";
const std::string SA_MAGR_NAME = "distributed.sa.manager";
const std::string KV_NAME = "distrubitedKv";
const std::string RDB_NAME = "relational_store";
const std::string DP_DATA_OPERATE_BEHAVIOR = "DP_DATA_OPERATE_BEHAVIOR";
const int32_t SUBSYS_DISTRIBUTEDHARDWARE_DP = 205;
constexpr int32_t INVALID_UDID_LENGTH = 10;
constexpr int32_t SUBSTR_UDID_LENGTH = 5;
enum class BizScene : int32_t {
    DP_GET_SA = 1,
    DP_ADD_DATA = 2,
    DP_DELET_DATA = 3,
    DP_GET_DATA = 4,
    DP_SUBSCRIBE_DATA = 5,
    DP_UNSUBSCRIBE_DATA = 6,
    DP_SYNC_DATA = 7,
    DP_PUT_ACL_PROFILE = 8,
    DP_UPDATE_ACL_PROFILE = 9,
    DP_GET_TRUST_PROFILE = 10,
    DP_GET_ALL_TRUST_PROFILE = 11,
    DP_GET_ACL_PROFILE = 12,
    DP_GET_ALL_ACL_PROFILE = 13,
    DP_DELETE_ACL_PROFILE = 14,
    DP_PUT_SERVICE_PROFILE = 15,
    DP_PUT_CHAR_PROFILE = 16,
    DP_GET_DEVICE_PROFILE = 17,
    DP_GET_SERVICE_PROFILE = 18,
    DP_GET_CHAR_PROFILE = 19,
    DP_DELETE_SERVICE_PROFILE = 20,
    DP_DELETE_CHAR_PROFILE = 21,
    DP_SUBSCRIBE_DEVICE_PROFILE = 22,
    DP_UNSUNBSCRIBE_DEVICE_PROFILE = 23,
    DP_SYNC_DEVICE_PROFILE = 24,
};

enum class StageRes : int32_t {
    STAGE_IDLE = 0x0,
    STAGE_SUCC = 0x1,
    STAGE_FAIL = 0x2,
    STAGE_CANCEL = 0x3,
    STAGE_UNKNOW = 0x4,
};

enum class GetSaStage : int32_t {
    DP_CHECK_SA = 0x1,
    DP_LOAD_SA = 0x2,
    DP_SA_CHACK_AUTH = 0x3,
};

enum class BizState : int32_t {
    BIZ_STATE_START = 0x1,
    BIZ_STATE_END = 0x2,
    BIZ_STATE_CANCEL = 0x3,
};

enum class ProfileOperateStage : int32_t {
    DP_PROFILE_OPERATE = 0x1,
    DP_NOTIFY_PROFILE_CHANGE = 0x2,
};

class DpRadarHelper {
    DECLARE_SINGLE_INSTANCE(DpRadarHelper);
public:
    bool ReportCheckDpSa(int32_t stageRes);
    bool ReportLoadDpSa(int32_t stageRes);
    bool ReportLoadDpSaCb(int32_t stageRes);
    bool ReportSaCheckAuth(int32_t stageRes);
    bool ReportPutAclProfile(int32_t errCode, const AccessControlProfile& accessControlProfile);
    bool ReportUpdateAclProfile(int32_t errCode, const AccessControlProfile& accessControlProfile);
    bool ReportGetTrustProfile(int32_t errCode, const std::string& deviceId,
        const TrustDeviceProfile& trustDeviceProfile);
    bool ReportGetAllTrustProfile(int32_t errCode, std::vector<TrustDeviceProfile>& trustDeviceProfiles);
    bool ReportGetAclProfile(int32_t errCode, std::vector<AccessControlProfile>& accessControlProfiles);
    bool ReportGetAllAclProfile(int32_t errCode, std::vector<AccessControlProfile>& accessControlProfiles);
    bool ReportDeleteAclProfile(int32_t errCode);
    bool ReportPutServiceProfile(int32_t errCode, const ServiceProfile& serviceProfile);
    bool ReportPutServiceProfileBatch(int32_t errCode, const std::vector<ServiceProfile>& serviceProfiles);
    bool ReportPutCharProfile(int32_t errCode, const CharacteristicProfile& characteristicProfile);
    bool ReportPutCharProfileBatch(int32_t errCode,
        const std::vector<CharacteristicProfile>& characteristicProfiles);
    bool ReportGetDeviceProfile(int32_t errCode, const std::string& deviceId, DeviceProfile& deviceProfile);
    bool ReportGetServiceProfile(int32_t errCode,
        const std::string& deviceId, ServiceProfile& serviceProfile);
    bool ReportGetCharProfile(int32_t errCode,
        const std::string& deviceId, CharacteristicProfile& characteristicProfile);
    bool ReportDeleteServiceProfile(int32_t errCode, const std::string& deviceId);
    bool ReportDeleteCharProfile(int32_t errCode, const std::string& deviceId);
    bool ReportSubscribeDeviceProfile(int32_t errCode, const SubscribeInfo& subscribeInfo);
    bool ReportUnSubscribeDeviceProfile(int32_t errCode, const SubscribeInfo& subscribeInfo);
    bool ReportSyncDeviceProfile(int32_t errCode);
    bool ReportNotifyProfileChange(int32_t code);
    std::string GetPeerUdidList(const std::vector<TrustDeviceProfile>& trustDeviceProfiles);
    std::string GetPeerUdidList(const std::vector<AccessControlProfile>& accessControlProfiles);
    std::string GetPeerUdidList(const std::vector<ServiceProfile>& serviceProfiles);
    std::string GetPeerUdidList(const std::vector<CharacteristicProfile>& characteristicProfiles);
    bool IsDeviceProfileInit();
    void SetDeviceProfileInit(bool isInit);
private:
    std::string GetAnonyUdid(std::string udid);
    std::string GetLocalUdid();
    std::string GetPeerUdid(std::string udid);
    bool isInit_ = false;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_RADAR_HELPER_H