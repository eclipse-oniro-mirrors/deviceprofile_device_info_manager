/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DP_DEVICE_PROFILE_H
#define OHOS_DP_DEVICE_PROFILE_H

#include <cstdint>
#include <string>
#include "distributed_device_profile_constants.h"
#include "dp_parcel.h"

namespace OHOS {
namespace DistributedDeviceProfile {
class DeviceProfile : public DpParcel {
public:
    DeviceProfile()
        : deviceId_(""),
        deviceName_(""),
        manufactureName_(""),
        deviceModel_(""),
        storageCapability_(0),
        osSysCap_(""),
        osApiLevel_(0),
        osVersion_(""),
        osType_(0),
        isMultiUser_(false),
        userId_(DEFAULT_USER_ID),
        id_(0),
        devType_(""),
        manu_(""),
        sn_(""),
        productId_(""),
        productName_(""),
        subProductId_(""),
        hiv_(""),
        mac_(""),
        fwv_(""),
        hwv_(""),
        swv_(""),
        protType_(0),
        wiseUserId_(""),
        wiseDeviceId_(""),
        registerTime_(""),
        modifyTime_(""),
        shareTime_(""),
        accountId_(""),
        bleMac_(""),
        brMac_(""),
        sleMac_(""),
        setupType_(0),
        internalModel_("")
    {}
    ~DeviceProfile() = default;

    std::string GetDeviceId() const;
    void SetDeviceId(const std::string& deviceId);
    std::string GetDeviceName() const;
    void SetDeviceName(const std::string& deviceName);
    std::string GetManufactureName() const;
    void SetManufactureName(std::string manufactureName);
    std::string GetDeviceModel() const;
    void SetDeviceModel(const std::string& deviceModel);
    int64_t GetStorageCapability() const;
    void SetStorageCapability(int64_t storageCapability);
    std::string GetOsSysCap() const;
    void SetOsSysCap(const std::string& osSysCap);
    int32_t GetOsApiLevel() const;
    void SetOsApiLevel(int32_t osApiLevel);
    std::string GetOsVersion() const;
    void SetOsVersion(const std::string& osVersion);
    int32_t GetOsType() const;
    void SetOsType(int32_t osType);
    bool IsMultiUser() const;
    void SetIsMultiUser(bool isMultiUser);
    int32_t GetUserId() const;
    void SetUserId(int32_t userId);
    int32_t GetId() const;
    void SetId(int32_t id);
    std::string GetDevType() const;
    void SetDevType(const std::string& devType);
    std::string GetManu() const;
    void SetManu(const std::string& manu);
    std::string GetSn() const;
    void SetSn(const std::string& sn);
    std::string GetProductId() const;
    void SetProductId(const std::string& productId);
    std::string GetProductName() const;
    void SetProductName(const std::string& productName);
    std::string GetSubProductId() const;
    void SetSubProductId(const std::string& subProductId);
    std::string GetHiv() const;
    void SetHiv(const std::string& hiv);
    std::string GetMac() const;
    void SetMac(const std::string& mac);
    std::string GetFwv() const;
    void SetFwv(const std::string& fwv);
    std::string GetHwv() const;
    void SetHwv(const std::string& hwv);
    std::string GetSwv() const;
    void SetSwv(const std::string& swv);
    int32_t GetProtType() const;
    void SetProtType(int32_t protType);
    std::string GetWiseUserId() const;
    void SetWiseUserId(const std::string& wiseUserId);
    std::string GetWiseDeviceId() const;
    void SetWiseDeviceId(const std::string& wiseDeviceId);
    std::string GetRegisterTime() const;
    void SetRegisterTime(const std::string& registerTime);
    std::string GetModifyTime() const;
    void SetModifyTime(std::string modifyTime);
    std::string GetShareTime() const;
    void SetShareTime(const std::string& shareTime);
    std::string GetAccountId() const;
    void SetAccountId(const std::string& accountId);
    std::string GetInternalModel() const;
    void SetInternalModel(const std::string& internalModel);
    bool Marshalling(MessageParcel& parcel) const override;
    bool UnMarshalling(MessageParcel& parcel) override;
    bool operator!=(const DeviceProfile& deviceProfile) const;
    std::string dump() const override;
    std::string AnnoymizeDump() const;
    const std::string GetBleMac() const;
    void SetBleMac(const std::string& bleMac);
    const std::string GetBrMac() const;
    void SetBrMac(const std::string& brMac);
    const std::string GetSleMac() const;
    void SetSleMac(const std::string& sleMac);
    int32_t GetSetupType() const;
    void SetSetupType(int32_t setupType);
private:
    std::string deviceId_;
    std::string deviceName_;
    std::string manufactureName_;
    std::string deviceModel_;
    int64_t storageCapability_;
    std::string osSysCap_;
    int32_t osApiLevel_;
    std::string osVersion_;
    int32_t osType_;
    bool isMultiUser_;
    int32_t userId_;
    int32_t id_;
    std::string devType_;
    std::string manu_;
    std::string sn_;
    std::string productId_;
    std::string productName_ = "";
    std::string subProductId_;
    std::string hiv_;
    std::string mac_;
    std::string fwv_;
    std::string hwv_;
    std::string swv_;
    int32_t protType_;
    std::string wiseUserId_;
    std::string wiseDeviceId_;
    std::string registerTime_;
    std::string modifyTime_;
    std::string shareTime_;
    std::string accountId_;
    std::string bleMac_;
    std::string brMac_;
    std::string sleMac_;
    int32_t setupType_;
    std::string internalModel_;
};
} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // OHOS_DP_DEVICE_PROFILE_H
