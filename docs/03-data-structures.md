# 03 - 数据结构

> DeviceProfile 模块中的关键 struct、枚举、错误码及其生命周期和使用上下文。

所有数据类均继承自 `DpParcel`（扩展自 `Parcelable`），位于 `OHOS::DistributedDeviceProfile` 命名空间中。头文件路径：`common/include/interfaces/*.h`。

---

## 1. 核心数据结构

### 1.1 DeviceProfile

**源文件**：`common/include/interfaces/device_profile.h`
**基类**：`DpParcel`
**存储**：KV 存储（主存储）+ RDB `device_profile` 表（通过 ProfileDataManager / DeviceProfileDao）

```cpp
struct DeviceProfile : public DpParcel {
    std::string deviceId_ = "";
    std::string deviceName_ = "";
    std::string manufactureName_ = "";
    std::string deviceModel_ = "";
    int64_t storageCapability_ = 0;
    std::string osSysCap_ = "";
    int32_t osApiLevel_ = 0;
    std::string osVersion_ = "";
    int32_t osType_ = 0;
    bool isMultiUser_ = false;
    int32_t userId_ = DEFAULT_USER_ID; // -1
    // -- 以下为扩展字段（仅 RDB 存储） --
    int32_t id_ = 0;
    std::string devType_ = "";
    std::string manu_ = "";
    std::string sn_ = "";
    std::string productId_ = "";
    std::string productName_ = "";
    std::string subProductId_ = "";
    std::string hiv_ = "";
    std::string mac_ = "";
    std::string fwv_ = "";
    std::string hwv_ = "";
    std::string swv_ = "";
    int32_t protType_ = 0;
    std::string wiseUserId_ = "";
    std::string wiseDeviceId_ = "";
    std::string registerTime_ = "";
    std::string modifyTime_ = "";
    std::string shareTime_ = "";
    std::string accountId_ = "";
    std::string bleMac_ = "";
    std::string brMac_ = "";
    std::string sleMac_ = "";
    int32_t setupType_ = 0;
    std::string internalModel_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `deviceId_` | `std::string` | 设备唯一标识符（UDID） |
| `deviceName_` | `std::string` | 设备的可读名称 |
| `manufactureName_` | `std::string` | 制造商名称 |
| `deviceModel_` | `std::string` | 市场型号名称（如 "P60 Pro"） |
| `storageCapability_` | `int64_t` | 总存储容量，单位 KB，范围 [0..5368709120] |
| `osSysCap_` | `std::string` | 编码后的 OS 系统能力集（SysCap） |
| `osApiLevel_` | `int32_t` | OS API 级别，范围 [0..10000] |
| `osVersion_` | `std::string` | OS 版本号字符串 |
| `osType_` | `int32_t` | OS 类型标识符，范围 [0..10000]（10 = OH） |
| `isMultiUser_` | `bool` | 是否处于多用户模式 |
| `userId_` | `int32_t` | 用户 ID，-1 表示默认/单用户 |
| `id_` | `int32_t` | RDB 自动生成的行 ID |
| `devType_` | `std::string` | 设备类型字符串 |
| `manu_` | `std::string` | 制造商缩写 |
| `sn_` | `std::string` | 序列号 |
| `productId_` | `std::string` | 产品标识符 |
| `productName_` | `std::string` | 产品显示名称 |
| `subProductId_` | `std::string` | 子产品变体 ID |
| `hiv_` | `std::string` | 硬件镜像版本（HIV） |
| `mac_` | `std::string` | 设备 MAC 地址 |
| `fwv_` | `std::string` | 固件版本 |
| `hwv_` | `std::string` | 硬件版本 |
| `swv_` | `std::string` | 软件版本 |
| `protType_` | `int32_t` | 协议类型 |
| `wiseUserId_` | `std::string` | Wise 平台用户 ID |
| `wiseDeviceId_` | `std::string` | Wise 平台设备 ID |
| `registerTime_` | `std::string` | 首次注册时间戳 |
| `modifyTime_` | `std::string` | 最后修改时间戳 |
| `shareTime_` | `std::string` | 最后一次分享操作时间戳 |
| `accountId_` | `std::string` | 关联的账号 ID |
| `bleMac_` | `std::string` | BLE MAC 地址 |
| `brMac_` | `std::string` | BR/EDR MAC 地址 |
| `sleMac_` | `std::string` | SLE MAC 地址 |
| `setupType_` | `int32_t` | 设备设置类型 |
| `internalModel_` | `std::string` | 内部模型标识符 |

**生命周期**：在设备注册或首次数据同步时创建。核心字段持久化在 KV 存储中，全部字段存储在 RDB `device_profile` 表中。设备信息变更时更新。通过 `DeleteDeviceProfileBatch` 删除。

**使用场景**：设备发现、兼容性检查、设备信息展示。通过 `GetDeviceProfile(deviceId)` 和 `GetDeviceProfiles(filterOptions)` 查询。

---

### 1.2 ServiceProfile

**源文件**：`common/include/interfaces/service_profile.h`
**存储**：KV 存储 + RDB `service_profile` 表（通过 `device_profile_id` 外键关联到 device_profile）

```cpp
struct ServiceProfile : public DpParcel {
    std::string deviceId_ = "";
    std::string serviceName_ = "";
    std::string serviceType_ = "";
    bool isMultiUser_ = false;
    int32_t userId_ = DEFAULT_USER_ID; // -1
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `deviceId_` | `std::string` | 所属设备的 UDID |
| `serviceName_` | `std::string` | 服务名称（作为特征画像的命名空间） |
| `serviceType_` | `std::string` | 服务类型分类 |
| `isMultiUser_` | `bool` | 多用户模式标志 |
| `userId_` | `int32_t` | 用户作用域（-1 = 默认） |

**生命周期**：通过 `PutServiceProfile`（单条）或 `PutServiceProfileBatch`（批量）创建。每台设备可有多个服务画像。通过 `DeleteServiceProfile(deviceId, serviceName)` 删除。

**使用场景**：将特征画像归入服务命名空间下。API：`GetServiceProfile(deviceId, serviceName)`。

---

### 1.3 CharacteristicProfile

**源文件**：`common/include/interfaces/characteristic_profile.h`
**存储**：KV 存储 + RDB `characteristic_profile` 表

```cpp
struct CharacteristicProfile : public DpParcel {
    std::string deviceId_ = "";
    std::string serviceName_ = "";
    std::string characteristicKey_ = "";
    std::string characteristicValue_ = "";
    bool isMultiUser_ = false;
    int32_t userId_ = DEFAULT_USER_ID; // -1
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `deviceId_` | `std::string` | 所属设备的 UDID |
| `serviceName_` | `std::string` | 所属的父服务名称 |
| `characteristicKey_` | `std::string` | 能力键（如 "resolution"、"codec"） |
| `characteristicValue_` | `std::string` | 能力值（如 "1920x1080"、"h264"） |
| `isMultiUser_` | `bool` | 多用户模式标志 |
| `userId_` | `int32_t` | 用户作用域（-1 = 默认） |

**生命周期**：通过 `PutCharacteristicProfile` 或 `PutCharacteristicProfileBatch` 创建。通过 `DeleteCharacteristicProfile(deviceId, serviceName, characteristicKey)` 删除。

**使用场景**：存储实际的能力值，供分布式应用进行特性协商时查询。

---

### 1.4 AccessControlProfile

**源文件**：`common/include/interfaces/access_control_profile.h`
**存储**：RDB `access_control` 表

```cpp
struct AccessControlProfile : public DpParcel {
    int64_t accessControlId_ = 0;
    int64_t accesserId_ = 0;
    int64_t accesseeId_ = 0;
    std::string sessionKey_ = "";
    uint32_t bindType_ = 0;
    uint32_t authenticationType_ = 0;
    uint32_t bindLevel_ = 0;
    int32_t status_ = 0;
    int64_t validPeriod_ = 0;
    int64_t lastAuthTime_ = 0;
    std::string trustDeviceId_ = "";
    uint32_t deviceIdType_ = 0;
    std::string deviceIdHash_ = "";
    std::string extraData_ = "";
    Accesser accesser_;
    Accessee accessee_;
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `accessControlId_` | `int64_t` | 自动生成的唯一 ID |
| `accesserId_` | `int64_t` | 指向 `accesser` 表的外键 |
| `accesseeId_` | `int64_t` | 指向 `accessee` 表的外键 |
| `sessionKey_` | `std::string` | 会话密钥（如适用） |
| `bindType_` | `uint32_t` | 绑定类型枚举值（参见 BindType 节） |
| `authenticationType_` | `uint32_t` | TEMPORARY（1）或 PERMANENT（2） |
| `bindLevel_` | `uint32_t` | 作用范围：USER（1）、SERVICE（2）、APP（3） |
| `status_` | `int32_t` | INACTIVE（0）或 ACTIVE（1） |
| `validPeriod_` | `int64_t` | 有效期，单位秒 |
| `lastAuthTime_` | `int64_t` | 最后认证时间戳 |
| `trustDeviceId_` | `std::string` | 该 ACL 所绑定的设备 UDID |
| `deviceIdType_` | `uint32_t` | 所用设备 ID 的类型 |
| `deviceIdHash_` | `std::string` | 设备 ID 的哈希值 |
| `extraData_` | `std::string` | 扩展数据（如 `IS_LNN_ACL` 标记） |
| `accesser_` | `Accesser` | 内嵌的 Accesser 信息 |
| `accessee_` | `Accessee` | 内嵌的 Accessee 信息 |

**生命周期**：通过 `PutAccessControlProfile` 创建。通过 `UpdateAccessControlProfile` 更新。通过 `DeleteAccessControlProfile(accessControlId)` 删除。当关联的信任设备被移除时级联删除。

**使用场景**：分布式场景中的授权检查。通过 `GetAccessControlProfile(queryParams)`、`GetAllAccessControlProfile()`、`GetAllAclIncludeLnnAcl()` 查询。

---

### 1.5 Accesser

**源文件**：`common/include/interfaces/accesser.h`
**存储**：RDB `accesser` 表

```cpp
struct Accesser : public DpParcel {
    int64_t accesserId_ = 0;
    std::string accesserDeviceId_ = "";
    int32_t accesserUserId_ = 0;
    std::string accesserAccountId_ = "";
    int64_t accesserTokenId_ = 0;
    std::string accesserBundleName_ = "";
    std::string accesserHapSignature_ = "";
    uint32_t accesserBindLevel_ = 0;
    std::string accesserDeviceName_ = "";
    std::string accesserServiceName_ = "";
    int32_t accesserCredentialId_ = 0;
    std::string accesserCredentialIdStr_ = "";
    int32_t accesserStatus_ = 0;
    int32_t accesserSessionKeyId_ = 0;
    int64_t accesserSKTimeStamp_ = 0;
    std::string accesserExtraData_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `accesserId_` | `int64_t` | 自动生成的唯一 ID |
| `accesserDeviceId_` | `std::string` | Accesser 的设备 UDID |
| `accesserUserId_` | `int32_t` | Accesser 的用户 ID |
| `accesserAccountId_` | `std::string` | Accesser 的账号 ID |
| `accesserTokenId_` | `int64_t` | Accesser 的调用者 token ID |
| `accesserBundleName_` | `std::string` | Accesser 的 bundle/包名 |
| `accesserHapSignature_` | `std::string` | Accesser 的 HAP 签名 |
| `accesserBindLevel_` | `uint32_t` | 作用范围：USER / SERVICE / APP |
| `accesserDeviceName_` | `std::string` | Accesser 的设备显示名称 |
| `accesserServiceName_` | `std::string` | Accesser 的服务名称 |
| `accesserCredentialId_` | `int32_t` | 凭证标识符 |
| `accesserCredentialIdStr_` | `std::string` | 凭证 ID 字符串形式 |
| `accesserStatus_` | `int32_t` | 活跃/非活跃状态 |
| `accesserSessionKeyId_` | `int32_t` | 关联的会话密钥 ID |
| `accesserSKTimeStamp_` | `int64_t` | 会话密钥时间戳 |
| `accesserExtraData_` | `std::string` | 扩展数据 |

**生命周期**：作为 `PutAccessControlProfile` 的一部分创建（ID 自动生成）。随信任设备移除而级联删除。

**使用场景**：标识信任关系的发起方。通过各种 `SELECT_ACCESSER_TABLE_WHERE_*` SQL 模式查询。

---

### 1.6 Accessee

**源文件**：`common/include/interfaces/accessee.h`
**存储**：RDB `accessee` 表

与 Accesser 结构对称，所有字段名前缀由 `accesser` 替换为 `accessee`。字段、生命周期和使用模式均相同。

**字段表**（与 Accesser 对称）：

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `accesseeId_` | `int64_t` | 自动生成的唯一 ID |
| `accesseeDeviceId_` | `std::string` | Accessee 的设备 UDID |
| `accesseeUserId_` | `int32_t` | Accessee 的用户 ID |
| `accesseeAccountId_` | `std::string` | Accessee 的账号 ID |
| `accesseeTokenId_` | `int64_t` | Accessee 的调用者 token ID |
| `accesseeBundleName_` | `std::string` | Accessee 的 bundle/包名 |
| `accesseeHapSignature_` | `std::string` | Accessee 的 HAP 签名 |
| `accesseeBindLevel_` | `uint32_t` | 作用范围：USER / SERVICE / APP |
| `accesseeDeviceName_` | `std::string` | Accessee 的设备显示名称 |
| `accesseeServiceName_` | `std::string` | Accessee 的服务名称 |
| `accesseeCredentialId_` | `int32_t` | 凭证标识符 |
| `accesseeCredentialIdStr_` | `std::string` | 凭证 ID 字符串形式 |
| `accesseeStatus_` | `int32_t` | 活跃/非活跃状态 |
| `accesseeSessionKeyId_` | `int32_t` | 关联的会话密钥 ID |
| `accesseeSKTimeStamp_` | `int64_t` | 会话密钥时间戳 |
| `accesseeExtraData_` | `std::string` | 扩展数据 |

---

### 1.7 TrustDeviceProfile

**源文件**：`common/include/interfaces/trust_device_profile.h`
**存储**：RDB `trust_device` 表

```cpp
struct TrustDeviceProfile : public DpParcel {
    std::string deviceId_ = "";
    uint32_t deviceIdType_ = static_cast<uint32_t>(DeviceIdType::MIN);
    std::string deviceIdHash_ = "";
    int32_t status_ = static_cast<int32_t>(Status::MIN);
    uint32_t bindType_ = static_cast<uint32_t>(BindType::MIN);
    int32_t peerUserId_ = -1;
    int32_t localUserId_ = -1;
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `deviceId_` | `std::string` | 远端设备 UDID |
| `deviceIdType_` | `uint32_t` | 类型枚举：UDID（1）、UUID（2）、SN（3） |
| `deviceIdHash_` | `std::string` | 设备 ID 的哈希值 |
| `status_` | `int32_t` | INACTIVE（0）/ ACTIVE（1） |
| `bindType_` | `uint32_t` | 绑定关系类型 |
| `peerUserId_` | `int32_t` | 远端设备的用户 ID（未知时为 -1） |
| `localUserId_` | `int32_t` | 本地用户 ID（单用户时为 -1） |

**生命周期**：在设备信任关系建立时创建。设备上线/下线时状态在 ACTIVE 和 INACTIVE 之间切换。撤销信任时删除，并级联删除其 ACL 条目。

**使用场景**：分布式操作前的信任状态查询。API：`GetTrustDeviceProfile(deviceId)`、`GetAllTrustDeviceProfile()`。

---

### 1.8 TrustedDeviceInfo

**源文件**：`common/include/interfaces/trusted_device_info.h`
**存储**：瞬态（不直接持久化；作为 `PutAllTrustedDevices` 的输入参数）

```cpp
struct TrustedDeviceInfo : public DpParcel {
    std::string networkId_ = "";
    int32_t authForm_ = BINDTYPE_INIT; // -1
    uint16_t deviceTypeId_ = 0;
    std::string osVersion_ = "";
    int32_t osType_ = 0;
    std::string udid_ = "";
    std::string uuid_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `networkId_` | `std::string` | SoftBus 网络标识符 |
| `authForm_` | `int32_t` | 认证形式（设备发现时使用的绑定类型） |
| `deviceTypeId_` | `uint16_t` | 设备类型（手机/平板/电视等） |
| `osVersion_` | `std::string` | OS 版本号字符串 |
| `osType_` | `int32_t` | OS 类型代码 |
| `udid_` | `std::string` | 设备唯一标识符（在 DP 中解析为 deviceId） |
| `uuid_` | `std::string` | 通用唯一标识符 |

**生命周期**：由 DeviceManager 在设备发现时通过 `PutAllTrustedDevices(deviceInfos)` 提供。用作创建/更新内部 TrustDeviceProfile 记录的输入数据。

**使用场景**：来自 DeviceManager 的批量输入，用于建立信任设备记录。

---

### 1.9 ServiceInfo

**源文件**：`common/include/interfaces/service_info.h`
**存储**：KV 存储（双层：设备绑定 + 全局服务注册表）

```cpp
struct ServiceInfo : public DpParcel {
    std::string udid_ = "";
    int32_t userId_ = DEFAULT_USER_ID; // -1
    int64_t displayId_ = DEFAULT_DISPLAY_ID; // -1
    int32_t serviceOwnerTokenId_ = DEFAULT_SERVICE_OWNER_TOKENID; // -1
    std::string serviceOwnerPkgName_ = "";
    int32_t serviceRegisterTokenId_ = DEFAULT_SERVICE_REGISTER_TOKENID; // -1
    int64_t serviceId_ = DEFAULT_SERVICE_ID; // -1
    int64_t timeStamp_ = DEFAULT_TIMESTAMP; // -1
    int8_t publishState_ = DEFAULT_PUBLISH_STATE; // -1
    std::string serviceType_ = "";
    std::string serviceName_ = "";
    std::string serviceDisplayName_ = "";
    std::string customData_ = "";
    std::string serviceCode_ = "";
    uint32_t dataLen_ = 0;
    std::string extraData_ = "";
    std::string version_ = "";
    std::string description_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `udid_` | `std::string` | 所属设备的 UDID |
| `userId_` | `int32_t` | 用户作用域 |
| `displayId_` | `int64_t` | 显示器标识符（如屏幕 ID） |
| `serviceOwnerTokenId_` | `int32_t` | 服务所有者进程的 token |
| `serviceOwnerPkgName_` | `std::string` | 服务所有者的包名 |
| `serviceRegisterTokenId_` | `int32_t` | 注册进程的 token |
| `serviceId_` | `int64_t` | 服务标识符（每设备唯一） |
| `timeStamp_` | `int64_t` | 注册/更新时间戳 |
| `publishState_` | `int8_t` | 服务发布状态 |
| `serviceType_` | `std::string` | 服务类型分类 |
| `serviceName_` | `std::string` | 服务名称 |
| `serviceDisplayName_` | `std::string` | 面向用户的可读显示名称 |
| `customData_` | `std::string` | 任意自定义数据 |
| `serviceCode_` | `std::string` | 服务代码标识符 |
| `dataLen_` | `uint32_t` | customData 的长度 |
| `extraData_` | `std::string` | 扩展数据 |
| `version_` | `std::string` | 服务版本号 |
| `description_` | `std::string` | 服务描述 |

**生命周期**：通过 `PutServiceInfo` 创建，通过 `DeleteServiceInfo(UserInfo)` 删除。相等性由 `(udid, userId, serviceId)` 三元组定义。按 `(udid, userId, serviceId)` 排序。

**使用场景**：更丰富的服务注册模型。API：`PutServiceInfo`、`DeleteServiceInfo`、`GetAllServiceInfoList`、`GetServiceInfosByUserInfo`。

---

### 1.10 LocalServiceInfo

**源文件**：`common/include/interfaces/local_service_info.h`
**存储**：RDB `local_service_info` 表

```cpp
struct LocalServiceInfo : public DpParcel {
    std::string bundleName_ = "";
    int32_t authBoxType_ = DEFAULT_AUTH_BOX_TYPE; // -1
    int32_t authType_ = DEFAULT_AUTH_TYPE; // -1
    int32_t pinExchangeType_ = DEFAULT_PIN_EXCHANGE_TYPE; // -1
    std::string pinCode_ = "";
    std::string description_ = "";
    std::string extraInfo_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `bundleName_` | `std::string` | 所属 bundle/包名 |
| `authBoxType_` | `int32_t` | 认证盒子类型 |
| `authType_` | `int32_t` | 认证类型 |
| `pinExchangeType_` | `int32_t` | PIN 码交换机制类型 |
| `pinCode_` | `std::string` | PIN 码值 |
| `description_` | `std::string` | 描述文本 |
| `extraInfo_` | `std::string` | 附加信息 |

**生命周期**：通过 `PutLocalServiceInfo` 创建。通过 `UpdateLocalServiceInfo` 更新。通过 `DeleteLocalServiceInfo(bundleName, pinExchangeType)` 删除。当更新或删除时，会触发对订阅者的 `NotifyPinCodeInvalid` 通知。

**使用场景**：本地服务认证元数据管理。API：`PutLocalServiceInfo`、`UpdateLocalServiceInfo`、`GetLocalServiceInfoByBundleAndPinType`、`DeleteLocalServiceInfo`。

---

### 1.11 ProductInfo

**源文件**：`common/include/interfaces/product_info.h`
**存储**：RDB `product_info` 表

```cpp
struct ProductInfo : public DpParcel {
    std::string productId_ = "";
    std::string model_ = "";
    std::string productName_ = "";
    std::string productShortName_ = "";
    std::string imageVersion_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `productId_` | `std::string` | 产品标识符 |
| `model_` | `std::string` | 型号名称 |
| `productName_` | `std::string` | 产品全称 |
| `productShortName_` | `std::string` | 产品简称 |
| `imageVersion_` | `std::string` | 系统镜像版本 |

**生命周期**：通过 `PutProductInfoBatch`（仅支持批量）创建。对每个构建版本不可变。由 `ProductInfoDao` 管理。

**使用场景**：按 productId 索引的产品元数据，用于设备图标查找和产品识别。

---

### 1.12 DeviceIconInfo

**源文件**：`common/include/interfaces/device_icon_info.h`
**存储**：RDB `device_icon_info` 表

```cpp
struct DeviceIconInfo : public DpParcel {
    int32_t id_ = 0;
    std::string productId_ = "";
    std::string internalModel_ = "";
    std::string subProductId_ = "";
    std::string imageType_ = "";
    std::string specName_ = "";
    std::string version_ = "";
    std::string wiseVersion_ = "";
    std::string url_ = "";
    std::vector<uint8_t> icon_;
    int64_t modifyTime_ = 0;
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `id_` | `int32_t` | 自动生成的行 ID |
| `productId_` | `std::string` | 关联的产品 ID |
| `internalModel_` | `std::string` | 内部模型标识符 |
| `subProductId_` | `std::string` | 子产品变体 ID |
| `imageType_` | `std::string` | 图标图片类型 |
| `specName_` | `std::string` | 规格名称（如屏幕尺寸等级） |
| `version_` | `std::string` | 图标数据版本 |
| `wiseVersion_` | `std::string` | Wise 平台版本 |
| `url_` | `std::string` | 远端图标 URL |
| `icon_` | `std::vector<uint8_t>` | 二进制图标数据（最大 4MB） |
| `modifyTime_` | `int64_t` | 最后修改时间戳 |

**生命周期**：通过 `PutDeviceIconInfoBatch`（仅支持批量）创建。由 `ProductInfoDao` 操作删除。唯一键为 `productId + internalModel + subProductId + imageType + specName`。

**使用场景**：用于分布式设备列表 UI 展示的设备图标元数据。通过 `GetDeviceIconInfos(filterOptions)` 查询。

---

### 1.13 BusinessEvent

**源文件**：`common/include/interfaces/business_event.h`
**存储**：KV 存储（通过 `BusinessEventAdapter`）

```cpp
struct BusinessEvent : public DpParcel {
    std::string businessKey_ = "";
    std::string businessValue_ = "";
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `businessKey_` | `std::string` | 业务事件键（分类 + 标识符） |
| `businessValue_` | `std::string` | 业务事件值/负载 |

**生命周期**：通过 `PutBusinessEvent` 创建。通过 `GetBusinessEvent` 查询。通过 `RegisterBusinessCallback` 通知已注册的回调。

**使用场景**：轻量级的业务级事件传播。`BusinessEventExt`（标准 `Parcelable`）用于 IPC 传输，独立于 `DpParcel` 层次结构。

---

### 1.14 DpSyncOptions

**源文件**：`common/include/interfaces/dp_sync_options.h`
**存储**：瞬态（仅作为 API 参数）

```cpp
struct DpSyncOptions : public DpParcel {
    SyncMode syncMode_ = SyncMode::PUSH_PULL;
    std::vector<std::string> syncDeviceIds_;
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `syncMode_` | `SyncMode` | PULL（0）、PUSH（1）或 PUSH_PULL（2） |
| `syncDeviceIds_` | `std::vector<std::string>` | 同步的目标设备 UDID 列表 |

**生命周期**：由调用方创建，传入 `SyncDeviceProfile()` 或 `SyncStaticProfile()`。不持久化。

**使用场景**：同步 API 调用的参数对象。

---

### 1.15 SubscribeInfo

**源文件**：`common/include/interfaces/dp_subscribe_info.h`
**存储**：RDB `subscribe_trust_info` 表（信任订阅）+ 内存中的订阅集合

```cpp
struct SubscribeInfo : public DpParcel {
    int32_t saId_ = -1;
    std::string subscribeKey_ = "";
    std::unordered_set<ProfileChangeType> subscribeChangeTypes_;
    sptr<IRemoteObject> listener_ = nullptr;
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `saId_` | `int32_t` | 订阅者 System Ability ID |
| `subscribeKey_` | `std::string` | 复合键模式（deviceId、deviceId+serviceName 或 deviceId+serviceName+charKey） |
| `subscribeChangeTypes_` | `std::unordered_set<ProfileChangeType>` | 需要监控的变更类型集合 |
| `listener_` | `sptr<IRemoteObject>` | 用于事件投递的 IPC 回调对象 |

**生命周期**：通过 `SubscribeDeviceProfile(subscribeInfo)` 创建。通过 `UnSubscribeDeviceProfile(subscribeInfo)` 删除。按 `(saId, subscribeKey)` 对去重。最大订阅数量：500。每个订阅最大变更类型数：6。

**使用场景**：注册对特定 Profile 变更事件的关注。订阅者由 `saId` 标识，订阅范围由 `subscribeKey` 定义，事件过滤器由 `subscribeChangeTypes` 定义。

---

### 1.16 UserInfo

**源文件**：`common/include/interfaces/user_info.h`
**存储**：瞬态（API 参数，用作 ServiceInfo 的查询键）

```cpp
struct UserInfo : public DpParcel {
    std::string udid = "";
    int32_t userId = DEFAULT_USER_ID; // -1
    int64_t serviceId = DEFAULT_SERVICE_ID; // -1
};
```

| 字段 | 类型 | 含义 |
|-------|------|---------|
| `udid` | `std::string` | 设备 UDID |
| `userId` | `int32_t` | 用户作用域 |
| `serviceId` | `int64_t` | 服务标识符 |

**生命周期**：瞬态查询参数。用作 `DeleteServiceInfo` 和 `GetServiceInfosByUserInfo` 的键。

**使用场景**：ServiceInfo 查找和删除的复合键。

---

## 2. 枚举定义

### 2.1 ProfileEvent（高层通知事件）

以下概念性分组来源于通知回调模式（非正式枚举定义）：

| 事件 | 触发条件 | 回调接口 |
|-------|---------|-------------------|
| `EVENT_PROFILE_CHANGED` | 任意 ProfileChangeType 匹配 | `IProfileChangeListener::OnProfileChange` |
| `EVENT_SYNC_COMPLETED` | KV 同步完成（成功或失败） | `ISyncCompletedCallback::OnSyncCompleted(results)` |
| `EVENT_DEVICE_PROFILE_INITED` | PostInit 序列完成 | `IDpInitedCallback::OnDpInited` |
| `EVENT_PINCODE_INVALID` | LocalServiceInfo 更新或删除 | `IPinCodeInvalidCallback::OnPinCodeInvalid` |

### 2.2 ProfileChangeType

**源文件**：`common/include/interfaces/distributed_device_profile_enums.h`

| 枚举值 | 数值 | 分类 | 描述 |
|------------|---------|----------|-------------|
| `PROFILE_CHANGE_TYPE_MIN` | 0 | 边界 | 下界哨兵值 |
| `TRUST_DEVICE_PROFILE_ADD` | 1 | Trust | 新增信任设备 |
| `TRUST_DEVICE_PROFILE_UPDATE` | 2 | Trust | 信任设备画像已修改 |
| `TRUST_DEVICE_PROFILE_DELETE` | 3 | Trust | 信任设备已移除 |
| `DEVICE_PROFILE_ADD` | 4 | Device | 新建设备画像 |
| `DEVICE_PROFILE_UPDATE` | 5 | Device | 设备画像已修改 |
| `DEVICE_PROFILE_DELETE` | 6 | Device | 设备画像已删除 |
| `SERVICE_PROFILE_ADD` | 7 | Service | 新建服务画像 |
| `SERVICE_PROFILE_UPDATE` | 8 | Service | 服务画像已修改 |
| `SERVICE_PROFILE_DELETE` | 9 | Service | 服务画像已删除 |
| `CHAR_PROFILE_ADD` | 10 | Characteristic | 新建特征画像 |
| `CHAR_PROFILE_UPDATE` | 11 | Characteristic | 特征画像已修改 |
| `CHAR_PROFILE_DELETE` | 12 | Characteristic | 特征画像已删除 |
| `TRUST_DEVICE_PROFILE_ACTIVE` | 13 | Trust+Status | 信任设备变为活跃 |
| `TRUST_DEVICE_PROFILE_INACTIVE` | 14 | Trust+Status | 信任设备变为非活跃 |
| `PROFILE_CHANGE_TYPE_MAX` | 15 | 边界 | 上界哨兵值 |

以上枚举值映射到 IPC 通知码（`DpIpcInterfaceCode` 中的 28-44）。

### 2.3 SyncMode

**源文件**：`common/include/interfaces/distributed_device_profile_enums.h`

| 枚举值 | 数值 | 行为 |
|------------|---------|----------|
| `MIN` | -1 | 边界哨兵值 |
| `PULL` | 0 | 从远端设备拉取 Profile 到本地 |
| `PUSH` | 1 | 将本地 Profile 推送到远端设备 |
| `PUSH_PULL` | 2 | 双向同步（默认模式） |
| `MAX` | 3 | 边界哨兵值 |

### 2.4 BindType

**源文件**：`common/include/interfaces/distributed_device_profile_enums.h`

| 枚举值 | 数值 | 含义 |
|------------|---------|---------|
| `MIN` | 0 | 边界哨兵值 |
| `SAME_ACCOUNT` | 1 | 同一用户账号下的设备 |
| `SHARE` | 2 | 基于分享的绑定（如近场分享） |
| `SAME_GROUP` | 3 | 同一信任组内的设备 |
| `POINT_TO_POINT` | 256 | 直接 P2P 绑定（用户发起） |
| `COMPATIBLE` | 512 | 兼容旧版本的绑定 |
| `DIFF_ACCOUNT` | 1282 | 不同用户账号之间的绑定 |
| `MAX` | 1283 | 边界哨兵值 |

注意其非连续范围：`[1-3]` 为账号/群组类绑定，`[256, 512, 1282]` 为特殊绑定模式。

### 2.5 DpIpcInterfaceCode

**源文件**：`common/include/interfaces/dp_ipc_interface_code.h`
**SAID**：6001

按功能区域分组：

#### 信任与 ACL（7-13）
| 码 | 值 | 方法 |
|------|-------|--------|
| `PUT_ACL_PROFILE` | 7 | `PutAccessControlProfile` |
| `UPDATE_ACL_PROFILE` | 8 | `UpdateAccessControlProfile` |
| `GET_TRUST_DEVICE_PROFILE` | 9 | `GetTrustDeviceProfile` |
| `GET_ALL_TRUST_DEVICE_PROFILE` | 10 | `GetAllTrustDeviceProfile` |
| `GET_ACL_PROFILE` | 11 | `GetAccessControlProfile` |
| `GET_ALL_ACL_PROFILE` | 12 | `GetAllAccessControlProfile` |
| `DELETE_ACL_PROFILE` | 13 | `DeleteAccessControlProfile` |

#### Profile CRUD（14-22、45-51）
| 码 | 值 | 方法 |
|------|-------|--------|
| `PUT_SERVICE_PROFILE` | 14 | `PutServiceProfile` |
| `PUT_SERVICE_PROFILE_BATCH` | 15 | `PutServiceProfileBatch` |
| `PUT_CHAR_PROFILE` | 16 | `PutCharacteristicProfile` |
| `PUT_CHAR_PROFILE_BATCH` | 17 | `PutCharacteristicProfileBatch` |
| `GET_DEVICE_PROFILE_NEW` | 18 | `GetDeviceProfile` |
| `GET_SERVICE_PROFILE` | 19 | `GetServiceProfile` |
| `GET_CHAR_PROFILE` | 20 | `GetCharacteristicProfile` |
| `DEL_SERVICE_PROFILE` | 21 | `DeleteServiceProfile` |
| `DEL_CHAR_PROFILE` | 22 | `DeleteCharacteristicProfile` |
| `PUT_ALL_TRUSTED_DEVICES` | 45 | `PutAllTrustedDevices` |
| `PUT_DEVICE_PROFILE_BATCH` | 46 | `PutDeviceProfileBatch` |
| `GET_DEVICE_PROFILES` | 47 | `GetDeviceProfiles` |
| `GET_DEVICE_ICON_INFOS` | 48 | `GetDeviceIconInfos` |
| `PUT_DEVICE_ICON_INFO_BATCH` | 49 | `PutDeviceIconInfoBatch` |
| `PUT_PRODUCT_INFO_BATCH` | 50 | `PutProductInfoBatch` |
| `DELETE_DEVICE_PROFILE_BATCH` | 51 | `DeleteDeviceProfileBatch` |

#### 订阅与同步（23-27、40-44、72、77）
| 码 | 值 | 方法 |
|------|-------|--------|
| `SUBSCRIBE_DEVICE_PROFILE` | 23 | `SubscribeDeviceProfile` |
| `UNSUBSCRIBE_DEVICE_PROFILE` | 24 | `UnSubscribeDeviceProfile` |
| `SYNC_DEVICE_PROFILE_NEW` | 25 | `SyncDeviceProfile` |
| `SEND_SUBSCRIBE_INFOS` | 26 | `SendSubscribeInfos` |
| `ON_SYNC_COMPLETED` | 27 | `OnSyncCompleted`（回调） |
| `ON_DEVICE_PROFILE_INITED` | 40 | DP 初始化完成通知（回调） |
| `SUBSCRIBE_DEVICE_PROFILE_INITED` | 41 | `SubscribeDeviceProfileInited` |
| `UNSUBSCRIBE_DEVICE_PROFILE_INITED` | 42 | `UnSubscribeDeviceProfileInited` |
| `ON_TRUST_DEVICE_PROFILE_ACTIVE` | 43 | 信任激活通知（回调） |
| `ON_TRUST_DEVICE_PROFILE_INACTIVE` | 44 | 信任失活通知（回调） |
| `SYNC_STATIC_PROFILE` | 72 | `SyncStaticProfile` |
| `SUBSCRIBE_SERVICE_INFO_CALLBACK` | 77 | `SubscribeAllServiceInfo` |

#### Profile 变更通知（28-39）
| 码 | 值 | 对应的 ProfileChangeType |
|------|-------|-------------------------------|
| `ON_TRUST_DEVICE_PROFILE_ADD` | 28 | TRUST_DEVICE_PROFILE_ADD（1） |
| `ON_TRUST_DEVICE_PROFILE_UPDATE` | 29 | TRUST_DEVICE_PROFILE_UPDATE（2） |
| `ON_TRUST_DEVICE_PROFILE_DELETE` | 30 | TRUST_DEVICE_PROFILE_DELETE（3） |
| `ON_DEVICE_PROFILE_ADD` | 31 | DEVICE_PROFILE_ADD（4） |
| `ON_DEVICE_PROFILE_UPDATE` | 32 | DEVICE_PROFILE_UPDATE（5） |
| `ON_DEVICE_PROFILE_DELETE` | 33 | DEVICE_PROFILE_DELETE（6） |
| `ON_SERVICE_PROFILE_ADD` | 34 | SERVICE_PROFILE_ADD（7） |
| `ON_SERVICE_PROFILE_UPDATE` | 35 | SERVICE_PROFILE_UPDATE（8） |
| `ON_SERVICE_PROFILE_DELETE` | 36 | SERVICE_PROFILE_DELETE（9） |
| `ON_CHAR_PROFILE_ADD` | 37 | CHAR_PROFILE_ADD（10） |
| `ON_CHAR_PROFILE_UPDATE` | 38 | CHAR_PROFILE_UPDATE（11） |
| `ON_CHAR_PROFILE_DELETE` | 39 | CHAR_PROFILE_DELETE（12） |

#### ServiceInfo（52-54、73-76）
| 码 | 值 | 方法 |
|------|-------|--------|
| `PUT_SERVICE_INFO` | 52 | `PutServiceInfo` |
| `DELETE_SERVICE_INFO` | 53 | `DeleteServiceInfo` |
| `GET_ALL_SERVICE_INFO_LIST` | 54 | `GetAllServiceInfoList` |
| `GET_SERVICE_INFO_BY_USER_INFO` | 73 | `GetServiceInfosByUserInfo` |
| `ON_SERVICE_INFO_INSERT` | 74 | ServiceInfo 已插入（回调） |
| `ON_SERVICE_INFO_UPDATE` | 75 | ServiceInfo 已更新（回调） |
| `ON_SERVICE_INFO_DELETE` | 76 | ServiceInfo 已删除（回调） |

#### 会话密钥（55-58）
| 码 | 值 | 方法 |
|------|-------|--------|
| `PUT_SESSION_KEY` | 55 | `PutSessionKey` |
| `GET_SESSION_KEY` | 56 | `GetSessionKey` |
| `UPDATE_SESSION_KEY` | 57 | `UpdateSessionKey` |
| `DELETE_SESSION_KEY` | 58 | `DeleteSessionKey` |

#### PinCode（59-61）
| 码 | 值 | 方法 |
|------|-------|--------|
| `ON_PINCODE_INVALID` | 59 | PinCode 失效通知（回调） |
| `SUBSCRIBE_PINCODE_INVALID` | 60 | `SubscribePinCodeInvalid` |
| `UNSUBSCRIBE_PINCODE_INVALID` | 61 | `UnSubscribePinCodeInvalid` |

#### 本地服务信息（62-65）
| 码 | 值 | 方法 |
|------|-------|--------|
| `PUT_LOCAL_SERVICE_INFO` | 62 | `PutLocalServiceInfo` |
| `UPDATE_LOCAL_SERVICE_INFO` | 63 | `UpdateLocalServiceInfo` |
| `GET_LOCAL_SERVICE_INFO_BY_BINDLE_AND_PINTYPE` | 64 | `GetLocalServiceInfoByBundleAndPinType` |
| `DELETE_LOCAL_SERVICE_INFO` | 65 | `DeleteLocalServiceInfo` |

#### ACL 扩展（66）
| 码 | 值 | 方法 |
|------|-------|--------|
| `GET_ALL_ACL_INCLUDE_LNN_ACL` | 66 | `GetAllAclIncludeLnnAcl` |

#### 业务事件（67-71）
| 码 | 值 | 方法 |
|------|-------|--------|
| `ON_BUSINESS_EVENT` | 67 | 业务事件通知（回调） |
| `REGISTER_BUSINESS_CALLBACK` | 68 | `RegisterBusinessCallback` |
| `UNREGISTER_BUSINESS_CALLBACK` | 69 | `UnRegisterBusinessCallback` |
| `PUT_BUSINESS_EVENT` | 70 | `PutBusinessEvent` |
| `GET_BUSINESS_EVENT` | 71 | `GetBusinessEvent` |

---

### 2.6 DistributedDeviceProfileErrorCode

**源文件**：`common/include/constants/distributed_device_profile_errors.h`
**错误码偏移量**：98566143

按类别分组：

#### 成功与通用类（0-65：范围 98566143 + [0..22]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_SUCCESS` | 0 | 成功 |
| `DP_INVALID_PARAMS` | 98566144 | 参数无效 |
| `DP_INTERFACE_CHECK_FAILED` | 98566145 | IPC 接口描述符不匹配 |
| `DP_GET_LOCAL_UDID_FAILED` | 98566146 | 无法获取本地 UDID |
| `DP_GET_SERVICE_FAILED` | 98566147 | 无法获取 SA 代理 |
| `DP_INIT_DB_FAILED` | 98566148 | 数据库初始化失败 |
| `DP_NOT_SUBSCRIBED` | 98566149 | 未找到订阅 |
| `DP_UNSUBSCRIBE_FAILED` | 98566150 | 取消订阅操作失败 |
| `DP_SUBSCRIBE_FAILED` | 98566151 | 订阅操作失败 |
| `DP_SUBSCRIBE_LIMIT_EXCEEDED` | 98566152 | 订阅数量超限 |
| `DP_POST_TASK_FAILED` | 98566153 | 事件处理器投递任务失败 |
| `DP_DEVICE_SYNC_BUSY` | 98566154 | 同步正在进行中 |
| `DP_PERMISSION_DENIED` | 98566155 | 权限校验失败 |
| `DP_UNTRUSTED_GROUP` | 98566156 | 设备不在受信任组中 |
| `DP_NOT_INIT_DB` | 98566157 | 数据库未初始化 |
| `DP_GET_NETWORKID_FAILED` | 98566158 | 无法获取 network ID |
| `DP_FILE_FAILED_ERR` | 98566159 | 文件操作失败 |
| `DP_LOAD_SERVICE_ERR` | 98566160 | 无法加载 SA（瞬态错误，触发 SDK 重试） |
| `DP_PUT_DEVICE_CACHE_ERR` | 98566161 | 设备缓存写入失败 |
| `DP_PUT_SERVICE_CACHE_ERR` | 98566162 | 服务缓存写入失败 |
| `DP_PUT_CHARACTERISTIC_CACHE_ERR` | 98566163 | 特征缓存写入失败 |
| `DP_CACHE_EXIST` | 98566164 | 缓存条目已存在 |
| `DP_CACHE_NOT_EXIST` | 98566165 | 缓存条目未找到 |

#### Manager 初始化/反初始化（66-84：范围 98566143 + [23..41]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_IPC_REMOTE_OBJECT_NULLPTR` | 98566166 | IPC 远端对象为空 |
| `DP_GET_ACL_PROFILE_FAIL` | 98566167 | ACL 画像查询失败 |
| `DP_GET_TRUST_DEVICE_PROFILE_FAIL` | 98566168 | 信任设备画像查询失败 |
| `DP_GET_ALL_TRUST_DEVICE_PROFILE_FAIL` | 98566169 | 全部信任设备画像查询失败 |
| `DP_PUT_ACL_PROFILE_FAIL` | 98566170 | ACL 写入失败 |
| `DP_UPDATE_ACL_PROFILE_FAIL` | 98566171 | ACL 更新失败 |
| `DP_UNLOAD_HANDLER_NULLPTR` | 98566172 | 卸载处理器为空 |
| `DP_CACHE_INIT_FAIL` | 98566173 | 缓存初始化失败 |
| `DP_DEVICE_MANAGER_INIT_FAIL` | 98566174 | DeviceProfileManager 初始化失败 |
| `DP_TRUST_PROFILE_MANAGER_INIT_FAIL` | 98566175 | TrustProfileManager 初始化失败 |
| `DP_DEVICE_PROFILE_MANAGER_INIT_FAIL` | 98566176 | DeviceProfileManager 初始化失败 |
| `DP_SUBSCRIBE_PROFILE_MANAGER_INIT_FAIL` | 98566177 | SubscribeProfileManager 初始化失败 |
| `DP_PROFILE_DATA_MANAGER_INIT_FAIL` | 98566178 | ProfileDataManager 初始化失败 |
| `DP_CONTENT_SENSOR_MANAGER_INIT_FAIL` | 98566179 | ContentSensorManager 初始化失败 |
| `DP_CACHE_UNINIT_FAIL` | 98566180 | 缓存反初始化失败 |
| `DP_DEVICE_MANAGER_UNINIT_FAIL` | 98566181 | DeviceProfileManager 反初始化失败 |
| `DP_TRUST_PROFILE_MANAGER_UNINIT_FAIL` | 98566182 | TrustProfileManager 反初始化失败 |
| `DP_DEVICE_PROFILE_MANAGER_UNINIT_FAIL` | 98566183 | DeviceProfileManager 反初始化失败 |
| `DP_SUBSCRIBE_TRUST_PROFILE_MANAGER_UNINIT_FAIL` | 98566184 | 订阅信任管理器反初始化失败 |
| `DP_SUBSCRIBE_DEVICE_PROFILE_MANAGER_UNINIT_FAIL` | 98566185 | 订阅设备管理器反初始化失败 |
| `DP_CONTENT_SENSOR_MANAGER_UNINIT_FAIL` | 98566186 | ContentSensorManager 反初始化失败 |
| `DP_CS_COLLECTOR_HANDLER_INIT_FAIL` | 98566187 | 内容传感器采集器 handler 初始化失败 |
| `DP_CS_POST_TASK_FAIL` | 98566188 | 内容传感器发布任务失败 |

#### KV Store（89-96：范围 98566143 + [46..61]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_KV_DB_PTR_NULL` | 98566189 | KV DB 指针为空 |
| `DP_KV_DB_INIT_FAIL` | 98566190 | KV DB 初始化失败 |
| `DP_REGISTER_KV_DATA_LISTENER_FAILED` | 98566191 | 注册 KV 数据变更监听器失败 |
| `DP_UNREGISTER_KV_DATA_LISTENER_FAILED` | 98566192 | 注销 KV 数据变更监听器失败 |
| `DP_REGISTER_KV_SYNC_LISTENER_FAILED` | 98566193 | 注册 KV 同步监听器失败 |
| `DP_UNREGISTER_KV_SYNC_LISTENER_FAILED` | 98566194 | 注销 KV 同步监听器失败 |
| `DP_REGISTER_KV_DEATH_LISTENER_FAILED` | 98566195 | 注册 KV 死亡监听器失败 |
| `DP_UNREGISTER_KV_DEATH_LISTENER_FAILED` | 98566196 | 注销 KV 死亡监听器失败 |
| `DP_PUT_KV_DB_FAIL` | 98566197 | KV 写入操作失败 |
| `DP_DEL_KV_DB_FAIL` | 98566198 | KV 删除操作失败 |
| `DP_GET_KV_DB_FAIL` | 98566199 | KV 获取操作失败 |

#### 通用 Manager（97-105：范围 98566143 + [57..62]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_MANAGER_INIT_FAIL` | 98566200 | 通用 Manager 初始化失败 |
| `DP_EXCEED_MAX_SIZE_FAIL` | 98566201 | 数据超出最大尺寸限制 |
| `DP_NOT_FOUND_FAIL` | 98566202 | 数据未找到 |
| `DP_SYNC_DEVICE_FAIL` | 98566203 | 设备同步失败 |
| `DP_KV_SYNC_FAIL` | 98566204 | KV 同步失败 |
| `DP_GET_SA_MANAGER_FAIL` | 98566205 | 无法获取 SA 管理器 |
| `DP_GET_SA_PROXY_FAIL` | 98566206 | 无法获取 SA 代理 |
| `DP_PARSE_PERMISSION_JSON_FAIL` | 98566207 | 权限 JSON 解析失败 |

#### RDB（109-115：范围 98566143 + [66..93]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_RDBADAPTER_PUT_FAIL` | 98566209 | RDB 写入失败 |
| `DP_RDBADAPTER_DELETE_FAIL` | 98566210 | RDB 删除失败 |
| `DP_RDBADAPTER_UPDATE_FAIL` | 98566211 | RDB 更新失败 |
| `DP_RDBADAPTER_CREATE_TABLE_FAIL` | 98566212 | RDB 创建表失败 |
| `DP_RDBADAPTER_INIT_FAIL` | 98566213 | RDB 适配器初始化失败 |
| `DP_GET_RDBSTORE_FAIL` | 98566214 | 无法获取 RDB 存储 |
| `DP_RDBADAPTER_TABLE_NOT_EXIST` | 98566215 | RDB 表未找到 |
| `DP_UNINIT_FAIL` | 98566216 | 通用反初始化失败 |
| `DP_PUT_SUBSCRIBE_TRUST_INFO_TABLE_FAIL` | 98566217 | 订阅信任信息表写入失败 |
| `DP_PUT_TRUST_DEVICE_PROFILE_FAIL` | 98566218 | 信任设备写入失败 |
| `DP_NOTIFY_TRUST_DEVICE_FAIL` | 98566219 | 信任设备通知失败 |
| `DP_GET_RESULTSET_FAIL` | 98566220 | RDB 结果集获取失败 |
| `DP_NOT_FIND_DATA` | 98566221 | RDB 中未找到数据 |
| `DP_NOTIFY_STATUS_UPDATE_FAIL` | 98566222 | 状态更新通知失败 |
| `DP_RESULTSET_TO_VALUES_FAIL` | 98566223 | 结果集转 Values 失败 |
| `DP_DELETE_TRUST_DEVICE_PROFILE_FAIL` | 98566224 | RDB 信任设备删除失败 |
| `DP_DELETE_ACCESS_CONTROL_PROFILE_FAIL` | 98566225 | RDB ACL 画像删除失败 |
| `DP_CREATE_TABLE_FAIL` | 98566226 | RDB 创建表失败 |
| `DP_CREATE_UNIQUE_INDEX_FAIL` | 98566227 | RDB 创建唯一索引失败 |
| `DP_PUT_ACCESSER_PROFILE_FAIL` | 98566228 | Accesser 画像写入失败 |
| `DP_PUT_ACCESSEE_PROFILE_FAIL` | 98566229 | Accessee 画像写入失败 |
| `DP_UPDATE_TRUST_DEVICE_PROFILE_FAIL` | 98566230 | 信任设备更新失败 |
| `DP_DELETE_ACCESSER_PROFILE_FAIL` | 98566231 | Accesser 画像删除失败 |
| `DP_DELETE_ACCESSEE_PROFILE_FAIL` | 98566232 | Accessee 画像删除失败 |

#### IPC / SA（116-122：范围 98566143 + [90..104]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_GET_SYSTEM_ABILITY_FAIL` | 98566233 | 无法获取系统能力 |
| `DP_GET_PROXY_FAIL` | 98566234 | 无法获取 IPC 代理 |
| `DP_WRITE_PARCEL_FAIL` | 98566235 | Parcel 写入失败 |
| `DP_READ_PARCEL_FAIL` | 98566236 | Parcel 读取失败 |
| `DP_UNLOAD_SA_FAIL` | 98566237 | SA 卸载失败 |
| `DP_UPDATE_ACCESSER_PROFILE_FAIL` | 98566238 | Accesser 画像更新失败 |
| `DP_UPDATE_ACCESSEE_PROFILE_FAIL` | 98566239 | Accessee 画像更新失败 |

#### Sync（123-134：范围 98566143 + [97..104]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_SYNC_INIT_FAILED` | 98566240 | 同步初始化失败 |
| `DP_SYNC_PROFILE_FAILED` | 98566241 | Profile 同步失败 |
| `DP_UNSUPPORTED_METHOD` | 98566242 | 不支持的方法 |
| `DP_NO_MEMORY` | 98566243 | 内存不足 |
| `DP_SESSION_ERROR` | 98566244 | 会话错误 |
| `DP_INVALID_PARAM` | 98566245 | 参数无效 |
| `DP_CREATE_SESSION_FAILED` | 98566246 | 会话创建失败 |
| `DP_RUN_LOADED_FUNCTION_FAILED` | 98566247 | 加载的函数执行失败 |
| `DP_LOAD_SYNC_ADAPTER_FAILED` | 98566248 | 同步适配器加载失败 |
| `DP_UPDATE_ACL_NOT_ALLOW` | 98566249 | ACL 更新不被允许 |
| `DP_RDB_DB_PTR_NULL` | 98566250 | RDB 指针为空 |
| `DP_NOTIFY_ACCESS_CONTROL_FAIL` | 98566251 | ACL 通知失败 |
| `DP_DM_ADAPTER_INIT_FAIL` | 98566252 | DMAdapter 初始化失败 |
| `DP_DATA_EXISTS` | 98566253 | 数据已存在 |

#### 静态能力（135-144：范围 98566143 + [111..118]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_STATIC_COLLECT_FAIL` | 98566254 | 静态能力采集失败 |
| `DP_LOAD_STATIC_CAP_FAIL` | 98566255 | 静态能力加载失败 |
| `DP_LOAD_STATIC_INFO_FAIL` | 98566256 | 静态信息加载失败 |
| `DP_GET_STATIC_CAP_FAIL` | 98566257 | 静态能力获取失败 |
| `DP_GET_STATIC_INFO_FAIL` | 98566258 | 静态信息获取失败 |
| `DP_PARSE_STATIC_CAP_FAIL` | 98566259 | 静态能力解析失败 |
| `DP_PARSE_STATIC_INFO_FAIL` | 98566260 | 静态信息解析失败 |
| `DP_LOAD_JSON_FILE_FAIL` | 98566261 | JSON 文件加载失败 |

#### 开关画像（145-158：范围 98566143 + [119..136]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_SET_SWITCH_CHARPROFILE_FAIL` | 98566262 | 设置开关特征画像失败 |
| `DP_NOTIFYSWITCHUPDATE_FAIL` | 98566263 | 开关更新通知失败 |
| `DP_PUT_CHAR_BATCH_FAIL` | 98566264 | 特征画像批量写入失败 |
| `DP_GET_SWITCH_FAIL` | 98566265 | 开关获取失败 |
| `DP_GET_NETWORKID_BY_UDID_FAIL` | 98566266 | 从 UDID 查找 networkId 失败 |
| `DP_GET_UDID_BY_NETWORKID_FAIL` | 98566267 | 从 networkId 查找 UDID 失败 |
| `DP_GET_SERVICENAME_BY_POS_FAIL` | 98566268 | 按位置获取服务名称失败 |
| `DP_GENERATE_SWITCH_NOTIFY_FAIL` | 98566269 | 生成开关通知失败 |
| `DP_LOAD_SWITCH_JSON_FAIL` | 98566270 | 开关 JSON 加载失败 |
| `DP_GET_SWITCH_INFO_FAIL` | 98566271 | 开关信息获取失败 |
| `DP_INIT_SWITCH_PROFILE_MANAGER_FAIL` | 98566272 | SwitchProfileManager 初始化失败 |
| `DP_NULLPTR` | 98566273 | 空指针 |
| `DP_SUBSCRIBE_INITED_FALI` | 98566274 | 订阅初始化通知失败 |
| `DP_GET_DEVICE_ENTRIES_FAIL` | 98566275 | 获取设备条目失败 |
| `DP_RDB_DATABASE_RESTORE_FAIL` | 98566276 | RDB 数据库恢复失败 |

#### 多用户（159-166：范围 98566143 + [134..140]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_GET_FOREGROUND_ID_FAIL` | 98566277 | 获取前台用户 ID 失败 |
| `DP_GET_MULTI_USER_PROFILE_PARAMS_INVALID` | 98566278 | 多用户参数无效 |
| `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID` | 98566279 | 本地画像非前台用户 |
| `DP_GET_USER_ID_IS_NOT_TRUSTED` | 98566280 | 用户 ID 不受信任 |
| `DP_MULTI_USER_MANAGER_INIT_FAIL` | 98566281 | MultiUserManager 初始化失败 |
| `DP_MULTI_USER_MANAGER_UNINIT_FAIL` | 98566282 | MultiUserManager 反初始化失败 |
| `DP_DM_ADAPTER_UNINIT_FAIL` | 98566283 | DMAdapter 反初始化失败 |

#### 画像数据 / DAO（167-195：范围 98566143 + [141..170]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_PUT_DEVICE_ICON_INFO_FAIL` | 98566284 | 设备图标信息写入失败 |
| `DP_DEL_DEVICE_ICON_INFO_FAIL` | 98566286 | 设备图标信息删除失败 |
| `DP_UPDATE_DEVICE_ICON_INFO_FAIL` | 98566287 | 设备图标信息更新失败 |
| `DP_PUT_PRODUCT_INFO_FAIL` | 98566288 | 产品信息写入失败 |
| `DP_DEL_PRODUCT_INFO_FAIL` | 98566289 | 产品信息删除失败 |
| `DP_UPDATE_PRODUCT_INFO_FAIL` | 98566290 | 产品信息更新失败 |
| `DP_RDB_PUT_SERVICE_PROFILE_FAIL` | 98566291 | 服务画像 RDB 写入失败 |
| `DP_RDB_DELETE_SERVICE_PROFILE_FAIL` | 98566292 | 服务画像 RDB 删除失败 |
| `DP_RDB_UPDATE_SERVICE_PROFILE_FAIL` | 98566293 | 服务画像 RDB 更新失败 |
| `DP_RDB_GET_SERVICE_PROFILE_FAIL` | 98566294 | 服务画像 RDB 获取失败 |
| `DP_RDB_SET_SERVICE_PROFILE_ID_FAIL` | 98566295 | 服务画像 ID 设置失败 |
| `DP_DEVICE_PROFILE_NOT_FOUND` | 98566296 | 设备画像未找到 |
| `DP_SERVICE_PROFILE_NOT_FOUND` | 98566297 | 服务画像未找到 |
| `DP_DEVICE_PROFILE_DAO_INIT_FAIL` | 98566298 | DeviceProfileDao 初始化失败 |
| `DP_SERVICE_PROFILE_DAO_INIT_FAIL` | 98566299 | ServiceProfileDao 初始化失败 |
| `DP_CHAR_PROFILE_DAO_INIT_FAIL` | 98566300 | CharProfileDao 初始化失败 |
| `DP_PRODUCT_INFO_DAO_INIT_FAIL` | 98566301 | ProductInfoDao 初始化失败 |
| `DP_DEVICE_ICON_INFO_DAO_INIT_FAIL` | 98566302 | DeviceIconInfoDao 初始化失败 |
| `DP_DEVICE_PROFILE_DAO_UNINIT_FAIL` | 98566303 | DeviceProfileDao 反初始化失败 |
| `DP_SERVICE_PROFILE_DAO_UNINIT_FAIL` | 98566304 | ServiceProfileDao 反初始化失败 |
| `DP_CHAR_PROFILE_DAO_UNINIT_FAIL` | 98566305 | CharProfileDao 反初始化失败 |
| `DP_PRODUCT_INFO_DAO_UNINIT_FAIL` | 98566306 | ProductInfoDao 反初始化失败 |
| `DP_DEVICE_ICON_INFO_DAO_UNINIT_FAIL` | 98566307 | DeviceIconInfoDao 反初始化失败 |
| `DP_CREATE_INDEX_FAIL` | 98566308 | 索引创建失败 |
| `DP_SETTINGSDATA_MANAGER_INIT_FAIL` | 98566309 | SettingsDataManager 初始化失败 |
| `DP_SETTINGSDATA_MANAGER_UNINIT_FAIL` | 98566310 | SettingsDataManager 反初始化失败 |
| `DP_PROFILE_DATA_MANAGER_UNINIT_FAIL` | 98566311 | ProfileDataManager 反初始化失败 |
| `DP_SERVICE_INFO_MANAGER_INIT_FAIL` | 98566312 | ServiceInfoManager 初始化失败 |
| `DP_PUT_SERVICE_INFO_FAIL` | 98566313 | ServiceInfo 写入失败 |
| `DP_DELETE_SERVICE_INFO_FAIL` | 98566314 | ServiceInfo 删除失败 |
| `DP_UPDATE_SERVICE_INFO_PROFILE_FAIL` | 98566315 | ServiceInfo 画像更新失败 |

#### Asset（196-206：范围 98566143 + [173..183]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_ASSET_DUPLICATED` | 98566316 | Asset 条目重复 |
| `DP_PUT_ASSET_ERROR` | 98566317 | Asset 写入失败 |
| `DP_UPDATE_ASSET_ERROR` | 98566318 | Asset 更新失败 |
| `DP_GET_ASSET_ERROE` | 98566319 | Asset 获取失败 |
| `DP_GET_ASSET_NOT_FIND` | 98566320 | Asset 条目未找到 |
| `DP_DELETE_ASSET_ERROR` | 98566321 | Asset 删除失败 |
| `DP_PARSE_ASSET_ERROR` | 98566322 | Asset 数据解析失败 |
| `DP_SUBSCRIBE_PINCODE_INVALID` | 98566323 | PinCode 失效订阅失败 |
| `DP_SERVICE_INFO_PROFILE_EXISTS` | 98566324 | ServiceInfo 已存在 |
| `DP_LOCAL_SERVICE_INFO_EXISTS` | 98566325 | LocalServiceInfo 已存在 |
| `DP_PUT_LOCAL_SERVICE_INFO_FAIL` | 98566326 | LocalServiceInfo 写入失败 |
| `DP_DELETE_LOCAL_SERVICE_INFO_FAIL` | 98566327 | LocalServiceInfo 删除失败 |
| `DP_UPDATE_LOCAL_SERVICE_INFO_FAIL` | 98566328 | LocalServiceInfo 更新失败 |

#### 服务生命周期（207-225：范围 98566143 + [187..202]）
| 码 | 值 | 类别 |
|------|-------|----------|
| `DP_LOCAL_SERVICE_INFO_MANAGER_INIT_FAIL` | 98566329 | LocalServiceInfoManager 初始化失败 |
| `DP_SERVICE_ON_IDLE` | 98566330 | 服务进入空闲状态 |
| `DP_SERVICE_STOPPED` | 98566331 | 服务已停止（瞬态错误，SDK 会重试） |
| `DP_BUSINESS_EVENT_MANAGER_INIT_FAIL` | 98566332 | BusinessEventManager 初始化失败 |
| `DP_BUSINESS_EVENT_MANAGER_UNINIT_FAIL` | 98566333 | BusinessEventManager 反初始化失败 |
| `DP_PUT_BUSINESS_EVENT_FAIL` | 98566334 | BusinessEvent 写入失败 |
| `DP_GET_BUSINESS_EVENT_FAIL` | 98566335 | BusinessEvent 获取失败 |
| `DP_NOTIFY_BUSINESS_EVENT_FAIL` | 98566336 | BusinessEvent 通知失败 |
| `DP_INVALID_SQL_RESULT` | 98566337 | 无效的 SQL 查询结果 |
| `DP_DEVICE_UNSUPPORTED_SWITCH` | 98566338 | 设备不支持开关功能 |
| `DP_PRE_MIGRATION_DB_AVAILABLE` | 98566339 | 迁移前数据库可用 |
| `DP_PRE_MIGRATION_DB_UNAVAILABLE` | 98566340 | 迁移前数据库不可用 |
| `DP_NOT_NEED_MIGRATION` | 98566341 | 无需迁移 |
| `DP_NOT_SUPPORT` | 98566342 | 操作不支持 |

**错误码范围汇总：**

| 代码范围（偏移自 98566143） | 类别 | 数量 |
|-----------------------------------|----------|-------|
| 0 | 成功 | 1 |
| 1-22 | 通用 / 参数 / IPC | 21 |
| 23-45 | Manager 初始化 / 反初始化 | 23 |
| 46-61 | KV Store | 12 |
| 62 | SA Manager / Proxy | 2 |
| 66-93 | RDB 操作 | 28 |
| 94-95 | Accesser / Accessee 更新 | 2 |
| 97-104 | 同步 / 会话 | 8 |
| 107-111 | DM Adapter / 数据 | 3 |
| 111-118 | 静态能力 | 8 |
| 119-136 | 开关画像 | 18 |
| 134-140 | 多用户 | 7 |
| 141-170 | 画像数据 / DAO | 30 |
| 173-183 | Asset / LocalService | 11 |
| 187-199 | 服务生命周期 / 迁移 | 13 |

---

## 3. 辅助枚举

### 3.1 DeviceIdType

| 枚举值 | 数值 | 含义 |
|------------|---------|---------|
| `MIN` | 0 | 边界哨兵值 |
| `UDID` | 1 | 设备唯一标识符 |
| `UUID` | 2 | 通用唯一标识符 |
| `SN` | 3 | 序列号 |
| `MAX` | 4 | 边界哨兵值 |

### 3.2 BindLevel

| 枚举值 | 数值 | 作用范围 |
|------------|---------|-------|
| `MIN` | 0 | 边界哨兵值 |
| `USER` | 1 | 用户级绑定 |
| `SERVICE` | 2 | 服务级绑定 |
| `APP` | 3 | 应用级绑定 |
| `MAX` | 4 | 边界哨兵值 |

### 3.3 Status

| 枚举值 | 数值 | 含义 |
|------------|---------|---------|
| `MIN` | -1 | 边界哨兵值 |
| `INACTIVE` | 0 | 非活跃 / 离线 |
| `ACTIVE` | 1 | 活跃 / 在线 |
| `MAX` | 2 | 边界哨兵值 |

### 3.4 AuthenticationType

| 枚举值 | 数值 | 含义 |
|------------|---------|---------|
| `MIN` | 0 | 边界哨兵值 |
| `TEMPORARY` | 1 | 临时（如基于会话的） |
| `PERMANENT` | 2 | 永久（持久化信任） |
| `MAX` | 3 | 边界哨兵值 |

### 3.5 ProfileType（内部存储级分类）

| 枚举值 | 十六进制 | Profile 类型 |
|------------|-----|-------------|
| `PROFILE_TYPE_MIN` | 0x00 | 边界哨兵值 |
| `TRUST_DEVICE_PROFILE` | 0x10 | 信任设备画像 |
| `ACCESS_CONTROL_PROFILE` | 0x20 | 访问控制画像 |
| `DEVICE_PROFILE` | 0x30 | 设备画像 |
| `SERVICE_PROFILE` | 0x40 | 服务画像 |
| `CHAR_PROFILE` | 0x50 | 特征画像 |
| `PROFILE_TYPE_MAX` | 0x60 | 边界哨兵值 |

### 3.6 ChangeType（数据级变更分类）

| 枚举值 | 数值 | 含义 |
|------------|---------|---------|
| `CHANGE_TYPE_MIN` | 0 | 边界哨兵值 |
| `ADD` | 1 | 新建数据 |
| `UPDATE` | 2 | 现有数据已修改 |
| `DELETE` | 3 | 数据已移除 |
| `CHANGE_TYPE_MAX` | 4 | 边界哨兵值 |

### 3.7 SyncStatus

| 枚举值 | 数值 | 含义 |
|------------|---------|---------|
| `SUCCEEDED` | 0 | 同步成功完成 |
| `FAILED` | 1 | 同步失败 |

### 3.8 SwitchFlag

| 枚举值 | 数值 | 开关服务 |
|------------|---------|----------------|
| `SWITCH_FLAG_MIN` | -1 | 边界哨兵值 |
| `SWITCH_FLAG_KEY_MOUSE_EDGE_CROSSING` | 0 | `SwitchStatus_Key_Mouse_Edge_Crossing`（键鼠跨设备漫游） |
| `SWITCH_FLAG_KEY_DISTRIBUTED_PASTEBOARD` | 1 | `SwitchStatus_Key_Distributed_Pasteboard`（分布式剪贴板） |
| `SWITCH_FLAG_DCSHARESWITCH` | 2 | `SwitchStatus_DcShareSwitch`（分布式分享） |
| `SWITCH_FLAG_WIFI_DISPLAY_SERVICE` | 3 | `SwitchStatus_Wifi_Display_Service`（无线投屏） |
| `SWITCH_FLAG_DISTRIBUTED_SUPER_MANAGER` | 4 | `SwitchStatus_Distributed_Super_Manager`（分布式超级管理器） |
| `SWITCH_FLAG_MAX` | 5 | 边界哨兵值 |

### 3.9 StaticCapabilityFlag

| 枚举值 | 数值 | 服务 |
|------------|---------|---------|
| `CAPABILITY_FLAG_MIN` | -1 | 边界哨兵值 |
| `CAPABILITY_FLAG_DMS` | 0 | `dmsfwk_svr_id`（分布式管理服务） |
| `CAPABILITY_FLAG_PASTE_BOARD` | 1 | `pasteboardService`（剪贴板服务） |
| `CAPABILITY_FLAG_DISTRIBUTED_FILE_DAEMON` | 2 | `distributedfiledaemon`（分布式文件守护进程） |
| `CAPABILITY_FLAG_MAX` | 3 | 边界哨兵值 |

---

## 4. 关键尺寸限制（来源于常量定义）

| 常量 | 值 | 适用范围 |
|----------|-------|------------|
| `MAX_STRING_LEN` | 4096 | 所有字符串字段 |
| `MAX_STORAGE_KB` | 5368709120 | DeviceProfile.storageCapability |
| `MAX_OS_API_LEVEL` | 10000 | DeviceProfile.osApiLevel |
| `MAX_OS_TYPE` | 10000 | DeviceProfile.osType |
| `MAX_PARAM_SIZE` | 20 | 查询参数数量 |
| `MAX_PROFILE_SIZE` | 10000 | Profile 批量操作大小 |
| `MAX_DEVICE_SIZE` | 1000 | 设备数组大小 |
| `MAX_SERVICE_SIZE` | 1000 | 服务数组大小 |
| `MAX_CHAR_SIZE` | 1000 | 特征数组大小 |
| `MAX_DB_SIZE` | 1000 | 每次操作的 DB 记录数 |
| `MAX_LISTENER_SIZE` | 100 | 监听器数量 |
| `MAX_EVENT_HANDLER_SIZE` | 50 | 事件处理器数量 |
| `MAX_DB_RECORD_SIZE` | 10000 | 总 DB 记录数 |
| `MAX_SUBSCRIBE_CHANGE_SIZE` | 6 | 每个订阅的变更类型数 |
| `MAX_INTERFACE_SIZE` | 60 | 接口方法数量 |
| `MAX_SUBSCRIBE_INFO_SIZE` | 500 | 总订阅数 |
| `MAX_SYNC_RESULTS_SIZE` | 50 | 同步结果条目数 |
| `MAX_SESSIONKEY_SIZE` | 8192 | 会话密钥字节数（8KB） |
| `MAX_ICON_SIZE` | 4194304 | 设备图标二进制数据（4MB） |
| `MAX_USER_ID` | 100000 | 用户 ID 最大值 |
| `MAX_SAID` | 16777215 | System Ability ID 最大值 |
| `MAX_TRUSTED_DEVICE_SIZE` | 1000 | 信任设备批量大小 |
