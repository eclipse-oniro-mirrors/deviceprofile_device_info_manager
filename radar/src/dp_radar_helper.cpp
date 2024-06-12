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

#include <cJSON.h>
#include <errors.h>
#include "hisysevent.h"
#include "content_sensor_manager_utils.h"
#include "distributed_device_profile_log.h"
#include "profile_utils.h"

namespace OHOS {
namespace DistributedDeviceProfile {
IMPLEMENT_SINGLE_INSTANCE(DpRadarHelper);
namespace {
const std::string TAG = "DpRadarHelper";
}
void DpRadarHelper::ReportCheckDpSa(int32_t stageRes)
{
    int32_t res = ERR_OK;
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetDeviceProfileService",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_CHECK_SA),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "TO_CALL_PKG", SA_MAGR_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetDeviceProfileService",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_CHECK_SA),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "TO_CALL_PKG", SA_MAGR_NAME,
            "ERROR_CODE", DP_LOAD_SERVICE_ERR);
    }
    if (res != ERR_OK) {
        HILOGE("ReportCheckDpSa fail");
    }
    return;
}

void DpRadarHelper::ReportLoadDpSa(int32_t stageRes)
{
    int32_t res = ERR_OK;
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_IDLE)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "LoadDeviceProfileService",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "TO_CALL_PKG", SA_MAGR_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "LoadDeviceProfileService",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "TO_CALL_PKG", SA_MAGR_NAME,
            "ERROR_CODE", DP_LOAD_SERVICE_ERR);
    }
    if (res != ERR_OK) {
        HILOGE("ReportLoadDpSa failed");
    }
    return;
}

void DpRadarHelper::ReportLoadDpSaCb(int32_t stageRes)
{
    int32_t res = ERR_OK;
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "LoadSystemAbilitySuccess",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "HOST_NAME", SA_MAGR_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "LoadSystemAbilityFail",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_LOAD_SA),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_NAME", SA_MAGR_NAME,
            "ERROR_CODE", DP_LOAD_SERVICE_ERR);
    }
    if (res != ERR_OK) {
        HILOGE("ReportLoadDpSaCb failed");
    }
    return;
}

void DpRadarHelper::ReportSaCheckAuth(int32_t stageRes)
{
    int res = ERR_OK;
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "IsCallerTrust",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_SA_CHACK_AUTH),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END));
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "IsCallerTrust",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SA),
            "BIZ_STAGE", static_cast<int32_t>(GetSaStage::DP_SA_CHACK_AUTH),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "ERROR_CODE", ERR_PERMISSION_DENIED);
    }
    if (res != ERR_OK) {
        HILOGE("ReportSaCheckAuth failed");
    }
    return;
}

void DpRadarHelper::ReportPutAclProfile(int32_t errCode, const AccessControlProfile& accessControlProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(accessControlProfile.GetAccessee().GetAccesseeDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", accessControlProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(accessControlProfile.GetAccessee().GetAccesseeDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", accessControlProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportPutAclProfile failed");
    }
    return;
}

void DpRadarHelper::ReportUpdateAclProfile(int32_t errCode, const AccessControlProfile& accessControlProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "UpdateAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_UPDATE_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(accessControlProfile.GetAccessee().GetAccesseeDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", accessControlProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "UpdateAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_UPDATE_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(accessControlProfile.GetAccessee().GetAccesseeDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", accessControlProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportUpdateAclProfile failed");
    }
    return;
}

void DpRadarHelper::ReportGetTrustProfile(int32_t errCode, const std::string& deviceId,
    const TrustDeviceProfile& trustDeviceProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetTrustDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_TRUST_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", trustDeviceProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetTrustDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_TRUST_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", trustDeviceProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetTrustProfile failed");
    }
    return;
}

void DpRadarHelper::ReportGetAllTrustProfile(int32_t errCode, std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    std::string extraInfo = "";
    size_t size = trustDeviceProfiles.size() > 0 ? (trustDeviceProfiles.size() - 1) : 0;
    for (size_t i = 0; i < trustDeviceProfiles.size(); i++) {
        extraInfo += trustDeviceProfiles[i].dump();
        if (i != size) {
            extraInfo += ",";
        }
    }
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetAllTrustDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_ALL_TRUST_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(trustDeviceProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", extraInfo);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetAllTrustDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_ALL_TRUST_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(trustDeviceProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", extraInfo);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetAllTrustProfile failed");
    }
    return;
}

void DpRadarHelper::ReportGetAclProfile(int32_t errCode, std::vector<AccessControlProfile>& accessControlProfiles)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    std::string extraInfo = "";
    size_t size = accessControlProfiles.size() > 0 ? (accessControlProfiles.size() - 1) : 0;
    for (size_t i = 0; i < accessControlProfiles.size(); i++) {
        extraInfo += accessControlProfiles[i].dump();
        if (i != size) {
            extraInfo += ",";
        }
    }
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(accessControlProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", extraInfo);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(accessControlProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", extraInfo);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetAclProfile failed");
    }
    return;
}

void DpRadarHelper::ReportGetAllAclProfile(int32_t errCode, std::vector<AccessControlProfile>& accessControlProfiles)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    std::string extraInfo = "";
    size_t size = accessControlProfiles.size() > 0 ? (accessControlProfiles.size() - 1) : 0;
    for (size_t i = 0; i < accessControlProfiles.size(); i++) {
        extraInfo += accessControlProfiles[i].dump();
        if (i != size) {
            extraInfo += ",";
        }
    }
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetAllAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_ALL_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(accessControlProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", extraInfo);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetAllAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_ALL_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(accessControlProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", extraInfo);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetAllAclProfile failed");
    }
    return;
}

void DpRadarHelper::ReportDeleteAclProfile(int32_t errCode)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "DeleteAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELETE_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "DeleteAccessControlProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELETE_ACL_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportDeleteAclProfile failed");
    }
    return;
}

void DpRadarHelper::ReportPutServiceProfile(int32_t errCode, const ServiceProfile& serviceProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutServiceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_IDLE),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(serviceProfile.GetDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", serviceProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutServiceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(serviceProfile.GetDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", serviceProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportPutServiceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportPutServiceProfileBatch(int32_t errCode, const std::vector<ServiceProfile>& serviceProfiles)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    std::string extraInfo = "";
    size_t size = serviceProfiles.size() > 0 ? (serviceProfiles.size() - 1) : 0;
    for (size_t i = 0; i < serviceProfiles.size(); i++) {
        extraInfo += serviceProfiles[i].dump();
        if (i != size) {
            extraInfo += ",";
        }
    }
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutServiceProfileBatch",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_IDLE),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(serviceProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", extraInfo);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutServiceProfileBatch",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(serviceProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", extraInfo);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportPutServiceProfileBatch failed");
    }
    return;
}

void DpRadarHelper::ReportPutCharProfile(int32_t errCode, const CharacteristicProfile& characteristicProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutCharacteristicProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_IDLE),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(characteristicProfile.GetDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", characteristicProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutCharacteristicProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(characteristicProfile.GetDeviceId()),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", characteristicProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportPutCharProfile failed");
    }
    return;
}

void DpRadarHelper::ReportPutCharProfileBatch(int32_t errCode,
    const std::vector<CharacteristicProfile>& characteristicProfiles)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    std::string extraInfo = "";
    size_t size = characteristicProfiles.size() > 0 ? (characteristicProfiles.size() - 1) : 0;
    for (size_t i = 0; i < characteristicProfiles.size(); i++) {
        extraInfo += characteristicProfiles[i].dump();
        if (i != size) {
            extraInfo += ",";
        }
    }
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutCharacteristicProfileBatch",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_IDLE),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(characteristicProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", extraInfo);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "PutCharacteristicProfileBatch",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_PUT_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID_LIST", GetPeerUdidList(characteristicProfiles),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", extraInfo);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportPutCharProfileBatch failed");
    }
    return;
}

void DpRadarHelper::ReportGetDeviceProfile(int32_t errCode, const std::string& deviceId, DeviceProfile& deviceProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", deviceProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", deviceProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetDeviceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportGetServiceProfile(int32_t errCode,
    const std::string& deviceId, ServiceProfile& serviceProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetServiceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", serviceProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetServiceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", serviceProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetServiceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportGetCharProfile(int32_t errCode,
    const std::string& deviceId, CharacteristicProfile& characteristicProfile)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetCharacteristicProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", characteristicProfile.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "GetCharacteristicProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_GET_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", characteristicProfile.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportGetCharProfile failed");
    }
    return;
}

void DpRadarHelper::ReportDeleteServiceProfile(int32_t errCode, const std::string& deviceId)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "DeleteServiceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELETE_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_IDLE),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "DeleteServiceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELETE_SERVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportDeleteServiceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportDeleteCharProfile(int32_t errCode, const std::string& deviceId)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "DeleteCharacteristicProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELETE_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_IDLE),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_START),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "DeleteCharacteristicProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_DELETE_CHAR_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "PEER_UDID", GetPeerUdid(deviceId),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportDeleteCharProfile failed");
    }
    return;
}

void DpRadarHelper::ReportSubscribeDeviceProfile(int32_t errCode, const SubscribeInfo& subscribeInfo)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "SubscribeDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SUBSCRIBE_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", subscribeInfo.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "SubscribeDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SUBSCRIBE_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", subscribeInfo.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportSubscribeDeviceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportUnSubscribeDeviceProfile(int32_t errCode, const SubscribeInfo& subscribeInfo)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "UnSubscribeDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_UNSUNBSCRIBE_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME,
            "EXTRA_INFO", subscribeInfo.dump());
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "UnSubscribeDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_UNSUNBSCRIBE_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode,
            "EXTRA_INFO", subscribeInfo.dump());
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportUnSubscribeDeviceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportSyncDeviceProfile(int32_t errCode)
{
    int res = DP_SUCCESS;
    int32_t stageRes = (errCode == DP_SUCCESS) ?
        static_cast<int32_t>(StageRes::STAGE_SUCC) : static_cast<int32_t>(StageRes::STAGE_FAIL);
    if (stageRes == static_cast<int32_t>(StageRes::STAGE_SUCC)) {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "SyncDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SYNC_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", RDB_NAME,
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME);
    } else {
        res = HiSysEventWrite(
            OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
            DP_DATA_OPERATE_BEHAVIOR,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "ORG_PKG", ORGPKG_NAME,
            "FUNC", "SyncDeviceProfile",
            "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SYNC_DEVICE_PROFILE),
            "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_PROFILE_OPERATE),
            "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_FAIL),
            "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
            "HOST_PKG", RDB_NAME,
            "LOCAL_UDID", GetLocalUdid(),
            "TO_CALL_PKG", RDB_NAME,
            "ERROR_CODE", errCode);
    }
    if (res != DP_SUCCESS) {
        HILOGE("ReportSyncDeviceProfile failed");
    }
    return;
}

void DpRadarHelper::ReportNotifyProfileChange(int32_t code)
{
    std::string funcName = "";
    switch (code) {
        case ProfileType::DEVICE_PROFILE * ChangeType::ADD:
            funcName = "NotifyDeviceProfileAdd";
            break;
        case ProfileType::DEVICE_PROFILE * ChangeType::UPDATE:
            funcName = "NotifyDeviceProfileUpdate";
            break;
        case ProfileType::DEVICE_PROFILE * ChangeType::DELETE:
            funcName = "NotifyDeviceProfileDelete";
            break;
        case ProfileType::SERVICE_PROFILE * ChangeType::ADD:
            funcName = "NotifyServiceProfileAdd";
            break;
        case ProfileType::SERVICE_PROFILE * ChangeType::UPDATE:
            funcName = "NotifyServiceProfileUpdate";
            break;
        case ProfileType::SERVICE_PROFILE * ChangeType::DELETE:
            funcName = "NotifyServiceProfileDelete";
            break;
        case ProfileType::CHAR_PROFILE * ChangeType::ADD:
            funcName = "NotifyCharProfileAdd";
            break;
        case ProfileType::CHAR_PROFILE * ChangeType::UPDATE:
            funcName = "NotifyCharProfileUpdate";
            break;
        case ProfileType::CHAR_PROFILE * ChangeType::DELETE:
            funcName = "NotifyCharProfileDelete";
            break;
    }
    int res = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::DEVICE_PROFILE,
        DP_DATA_OPERATE_BEHAVIOR,
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "ORG_PKG", ORGPKG_NAME,
        "FUNC", funcName,
        "BIZ_SCENE", static_cast<int32_t>(BizScene::DP_SYNC_DEVICE_PROFILE),
        "BIZ_STAGE", static_cast<int32_t>(ProfileOperateStage::DP_NOTIFY_PROFILE_CHANGE),
        "STAGE_RES", static_cast<int32_t>(StageRes::STAGE_SUCC),
        "BIZ_STATE", static_cast<int32_t>(BizState::BIZ_STATE_END),
        "HOST_PKG", RDB_NAME,
        "LOCAL_UDID", GetLocalUdid(),
        "TO_CALL_PKG", RDB_NAME);
    if (res != DP_SUCCESS) {
        HILOGE("ReportNotifyProfileChange failed");
    }
    return;
}

std::string DpRadarHelper::GetPeerUdidList(const std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    if (trustDeviceProfiles.size() == 0) {
        return "";
    }
    cJSON* deviceInfoJson = cJSON_CreateObject();
    if (deviceInfoJson == nullptr) {
        return "";
    }
    cJSON* peerUdidList = cJSON_CreateArray();
    if (peerUdidList == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    cJSON_AddItemToObject(deviceInfoJson, "PEER_UDID_LIST", peerUdidList);
    for (size_t i = 0; i < trustDeviceProfiles.size(); i++) {
        std::string udid = GetPeerUdid(trustDeviceProfiles[i].GetDeviceId());
        cJSON* object = cJSON_CreateString(udid.c_str());
        if (object == nullptr) {
            cJSON_Delete(deviceInfoJson);
            return "";
        }
        cJSON_AddItemToArray(peerUdidList, object);
    }
    char *peerDevUdidStr = cJSON_PrintUnformatted(deviceInfoJson);
    if (peerDevUdidStr == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    std::string peerUdidStr = std::string(peerDevUdidStr);
    cJSON_Delete(deviceInfoJson);
    cJSON_free(peerDevUdidStr);
    return peerUdidStr;
}

std::string DpRadarHelper::GetPeerUdidList(const std::vector<AccessControlProfile>& accessControlProfiles)
{
    if (accessControlProfiles.size() == 0) {
        return "";
    }
    cJSON* deviceInfoJson = cJSON_CreateObject();
    if (deviceInfoJson == nullptr) {
        return "";
    }
    cJSON* peerUdidList = cJSON_CreateArray();
    if (peerUdidList == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    cJSON_AddItemToObject(deviceInfoJson, "PEER_UDID_LIST", peerUdidList);
    for (size_t i = 0; i < accessControlProfiles.size(); i++) {
        std::string udid = GetPeerUdid(accessControlProfiles[i].GetAccessee().GetAccesseeDeviceId());
        cJSON* object = cJSON_CreateString(udid.c_str());
        if (object == nullptr) {
            cJSON_Delete(deviceInfoJson);
            return "";
        }
        cJSON_AddItemToArray(peerUdidList, object);
    }
    char *peerDevUdidStr = cJSON_PrintUnformatted(deviceInfoJson);
    if (peerDevUdidStr == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    std::string peerUdidStr = std::string(peerDevUdidStr);
    cJSON_Delete(deviceInfoJson);
    cJSON_free(peerDevUdidStr);
    return peerUdidStr;
}

std::string DpRadarHelper::GetPeerUdidList(const std::vector<ServiceProfile>& serviceProfiles)
{
    if (serviceProfiles.size() == 0) {
        return "";
    }
    cJSON* deviceInfoJson = cJSON_CreateObject();
    if (deviceInfoJson == nullptr) {
        return "";
    }
    cJSON* peerUdidList = cJSON_CreateArray();
    if (peerUdidList == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    cJSON_AddItemToObject(deviceInfoJson, "PEER_UDID_LIST", peerUdidList);
    for (size_t i = 0; i < serviceProfiles.size(); i++) {
        std::string udid = GetPeerUdid(serviceProfiles[i].GetDeviceId());
        cJSON* object = cJSON_CreateString(udid.c_str());
        if (object == nullptr) {
            cJSON_Delete(deviceInfoJson);
            return "";
        }
        cJSON_AddItemToArray(peerUdidList, object);
    }
    char *peerDevUdidStr = cJSON_PrintUnformatted(deviceInfoJson);
    if (peerDevUdidStr == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    std::string peerUdidStr = std::string(peerDevUdidStr);
    cJSON_Delete(deviceInfoJson);
    cJSON_free(peerDevUdidStr);
    return peerUdidStr;
}

std::string DpRadarHelper::GetPeerUdidList(const std::vector<CharacteristicProfile>& characteristicProfiles)
{
    if (characteristicProfiles.size() == 0) {
        return "";
    }
    cJSON* deviceInfoJson = cJSON_CreateObject();
    if (deviceInfoJson == nullptr) {
        return "";
    }
    cJSON* peerUdidList = cJSON_CreateArray();
    if (peerUdidList == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    cJSON_AddItemToObject(deviceInfoJson, "PEER_UDID_LIST", peerUdidList);
    for (size_t i = 0; i < characteristicProfiles.size(); i++) {
        std::string udid = GetPeerUdid(characteristicProfiles[i].GetDeviceId());
        cJSON* object = cJSON_CreateString(udid.c_str());
        if (object == nullptr) {
            cJSON_Delete(deviceInfoJson);
            return "";
        }
        cJSON_AddItemToArray(peerUdidList, object);
    }
    char *peerDevUdidStr = cJSON_PrintUnformatted(deviceInfoJson);
    if (peerDevUdidStr == nullptr) {
        cJSON_Delete(deviceInfoJson);
        return "";
    }
    std::string peerUdidStr = std::string(peerDevUdidStr);
    cJSON_Delete(deviceInfoJson);
    cJSON_free(peerDevUdidStr);
    return peerUdidStr;
}

std::string DpRadarHelper::GetAnonyUdid(std::string udid)
{
    if (udid.empty() || udid.length() < INVALID_UDID_LENGTH) {
        return "";
    }
    return udid.substr(0, SUBSTR_UDID_LENGTH) + "**" + udid.substr(udid.length() - SUBSTR_UDID_LENGTH);
}

std::string DpRadarHelper::GetLocalUdid()
{
    return GetAnonyUdid(ContentSensorManagerUtils::GetInstance().ObtainLocalUdid());
}

std::string DpRadarHelper::GetPeerUdid(std::string udid)
{
    std::string localUdid = ContentSensorManagerUtils::GetInstance().ObtainLocalUdid();
    return udid.compare(localUdid) == 0 ? "" : GetAnonyUdid(udid);
}

bool DpRadarHelper::IsDeviceProfileInit()
{
    return isInit_;
}

void DpRadarHelper::SetDeviceProfileInit(bool isInit)
{
    isInit_ = isInit;
}
} // namespace DistributedDeviceProfile
} // namespace OHOS