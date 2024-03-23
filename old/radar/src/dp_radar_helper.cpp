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

#include "dp_radar_helper.h"
#include <errors.h>
#include "hisysevent.h"
#include "device_profile_log.h"

namespace OHOS {
namespace DeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(DpRadarHelper);
bool DpRadarHelper::ReportCheckDpSa(struct RadarInfo info)
{
    int32_t res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_CHECK_SA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", info.bizState,
            "TO_CALL_PKG", info.toCallPkg);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_CHECK_SA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", info.bizState,
            "TO_CALL_PKG", info.toCallPkg,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportLoadDpSa(struct RadarInfo info)
{
    int32_t res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_IDLE)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", info.stageRes,
            "TO_CALL_PKG", info.toCallPkg);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", info.bizState,
            "TO_CALL_PKG", info.toCallPkg,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportLoadDpSaCb(struct RadarInfo info)
{
    int32_t res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_IDLE)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", info.stageRes,
            "HOST_NAME", info.hostName);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", info.bizState,
            "HOST_NAME", info.hostName,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportSaCheckAuth(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_SA_CHACK_AUTH),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", info.bizState);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_SA_CHACK_AUTH),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", info.bizState,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportGetData(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_DATA),
            "BIZ_STAGE", static_cast<int32_t>(GetDataStage::DP_GET_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg,
            "LOCAL_UDID", GetAnonyUdid(info.localUdid));
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_DATA),
            "BIZ_STAGE", static_cast<int32_t>(GetDataStage::DP_GET_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetAnonyUdid(info.localUdid),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportAddData(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_ADD_DATA),
            "BIZ_STAGE", static_cast<int32_t>(AddDataStage::DP_ADD_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetAnonyUdid(info.localUdid),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_ADD_DATA),
            "BIZ_STAGE", static_cast<int32_t>(AddDataStage::DP_ADD_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetAnonyUdid(info.localUdid),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportDeleteData(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELET_DATA),
            "BIZ_STAGE", static_cast<int32_t>(static_cast<int32_t>(DelDataStage::DP_DELET_DATA)),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg,
            "LOCAL_UDID", GetAnonyUdid(info.localUdid));
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELET_DATA),
            "BIZ_STAGE", static_cast<int32_t>(static_cast<int32_t>(DelDataStage::DP_DELET_DATA)),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetAnonyUdid(info.localUdid),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportSubscribeData(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_IDLE)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", "SubscribeProfileEvents",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SUBSCRIBE_DATA),
            "BIZ_STAGE", static_cast<int32_t>(SubscribeDataStage::DP_SUBSCRIBE_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "TO_CALL_PKG", kvNAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", "SubscribeProfileEvents",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SUBSCRIBE_DATA),
            "BIZ_STAGE", static_cast<int32_t>(SubscribeDataStage::DP_SUBSCRIBE_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "TO_CALL_PKG", kvNAME,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportNotifyDataChange(struct RadarInfo info)
{
    int32_t res = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
        DP_DATA_OPERATE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORGPKGNAME,
        "FUNC", info.funcName,
        "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SUBSCRIBE_DATA),
        "BIZ_STAGE", static_cast<int32_t>(SubscribeDataStage::DP_RECIVE_DATA_CHANGE),
        "STAGE_RES", info.stageRes,
        "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END));
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportUnsbscribeData(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_UNSUBSCRIBE_DATA),
            "BIZ_STAGE", static_cast<int32_t>(UnSubscribeDataStage::DP_UNSUBSCRIBE_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", info.funcName,
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_UNSUBSCRIBE_DATA),
            "BIZ_STAGE", static_cast<int32_t>(UnSubscribeDataStage::DP_UNSUBSCRIBE_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", info.hostName,
            "TO_CALL_PKG", info.toCallPkg,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportSyncData(struct RadarInfo info)
{
    int res = ERR_OK;
    if (info.stageRes == static_cast<int32_t>(StageRes::STAGE_IDLE)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", "SyncDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SYNC_DATA),
            "BIZ_STAGE", static_cast<int32_t>(SyncDataStage::DP_SYNC_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "HOST_PKG", info.hostName,
            "PEER_UDID", GetAnonyUdid(info.peerUdid),
            "TO_CALL_PKG", kvNAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKGNAME,
            "FUNC", "SyncDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SYNC_DATA),
            "BIZ_STAGE", static_cast<int32_t>(SyncDataStage::DP_SYNC_DATA),
            "STAGE_RES", info.stageRes,
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", info.hostName,
            "PEER_UDID", GetAnonyUdid(info.peerUdid),
            "TO_CALL_PKG", kvNAME,
            "ERROR_CODE", info.errCode);
    }
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

bool DpRadarHelper::ReportSyncDataCb(struct RadarInfo info)
{
    int32_t res = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
        DP_DATA_OPERATE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORGPKGNAME,
        "FUNC", info.funcName,
        "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SYNC_DATA),
        "BIZ_STAGE", static_cast<int32_t>(SyncDataStage::DP_RECIVE_SYNC_CALLBACK),
        "STAGE_RES", info.stageRes,
        "BIZ_STATE", info.bizState,
        "LOCAL_UDID", GetAnonyUdid(info.localUdid));
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

std::string DpRadarHelper::GetHostNameByServiceId(std::string serviceId)
{
    return hostNameMap_[serviceId];
}

std::string DpRadarHelper::GetStringUdidList(std::list<std::string> &udidList)
{
    std::string ret = "";
    for (auto it = udidList.begin(); it != udidList.end(); it++) {
        if ((*it).compare(udidList.back()) == 0) {
            ret += GetAnonyUdid(*it);
        } else {
            ret += GetAnonyUdid(*it);
            ret += ",";
        }
    }
    return ret;
}

int32_t DpRadarHelper::GetErrorCode(int32_t errCode, int32_t module)
{
    return ErrCodeOffset(SUBSYS_DISTRIBUTEDHARDWARE_DP, module) + errCode;
}

std::string DpRadarHelper::GetAnonyUdid(std::string udid)
{
    if (udid.empty() || udid.length() < INVALID_UDID_LENGTH) {
        return "";
    }
    return udid.substr(0, SUBSTR_UDID_LENGTH) + "**" + udid.substr(udid.length() - SUBSTR_UDID_LENGTH);
}
} // namespace DeviceProfile
} // namespace OHOS