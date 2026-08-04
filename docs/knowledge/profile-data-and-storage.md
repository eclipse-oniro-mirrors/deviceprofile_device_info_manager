# 画像数据与存储知识

> 本文只记录 DP 的画像三层层级、6 类 Profile 数据结构、三种存储后端与键前缀、多用户键分发、枚举与错误码。
> 服务分层与 SA 生命周期见 `service-architecture.md`；信任与访问控制见 `trust-acl-access-control.md`；同步与订阅通知见 `sync-subscription-notification.md`。
> 各数据流的**严格时序**见 `../01-workflows.md`。

## 1. 画像三层层级

| 层 | 粒度 | 复合键 | 数量关系 | 典型内容 | 变更频率 |
|----|------|--------|----------|----------|----------|
| `DeviceProfile`（顶层） | 每台物理设备 | `deviceId` | 每设备 1 个 | 品牌/型号/OS 标识 | 极少 |
| `ServiceProfile`（中间层） | 设备上的服务命名空间 | `deviceId + serviceName` | 每设备 0..N | 服务类型分类 | 偶尔 |
| `CharacteristicProfile`（叶子层） | 服务内的能力项 | `deviceId + serviceName + characteristicKey` | 每服务 0..N | 能力值（字符串） | 频繁 |

多用户模式下三层均携带 `userId` 与 `isMultiUser`，完整复合键为 `deviceId + serviceName + characteristicKey + userId`。键分发由 `MultiUserManager` 编排。

## 2. 存储后端矩阵

| 存储后端 | 组件 | 用途 | storeId / 库 / 表 | 锚点 |
|----------|------|------|--------------------|------|
| KV 分布式 | `distributeddata_inner` | OH 设备间自动同步；画像读写 | appId=`distributed_device_profile_service` | `device_profile_manager.cpp:46` |
| └ 动态画像 | KVAdapter | `DeviceProfile`/`ServiceProfile`/`CharProfile` | storeId=`dp_kv_store`，`autoSync=true`，`cloudConfig.enableCloud=true` | `device_profile_manager.cpp:60`、`kv_adapter.cpp:278` |
| └ 静态能力 | StaticProfileManager | 静态能力画像 | storeId=`dp_kv_static_store` | `static_profile_manager.cpp:52` |
| └ 业务事件 | BusinessEventAdapter | BusinessEvent | storeId=`dp_kv_store_business`，`autoSync=false`（本地） | `business_event_adapter.cpp:38` |
| └ 服务信息 | ServiceInfoKvAdapter + KVAdapter | ServiceInfo 双层 | 本地 storeId=`dp_kv_store_service_info_profile` + 同步 store | `service_info_kv_adapter.cpp:39`、`service_info_manager.h:72` |
| └ 开关 | SwitchAdapter | 开关状态 | appId=`distributed_device_profile_service` | `switch_profile_manager.cpp:31` |
| RDB(SQLite) | `native_rdb` | 关系完整性；外键级联 | — | — |
| └ ACL | RdbAdapter(TrustProfileManager) | trust/ACL | 库=`.../acl_db/dp_rdb.db`，version=`RDB_VERSION_5_1_2=3`；表 `trust_device_table`/`access_control_table`/`accesser_table`/`accessee_table`/`subscribe_trust_info_table` | `rdb_adapter.cpp:29`、`trust_profile_manager.h:156`、`dp_constants.cpp:247` |
| └ 结构化画像 | ProfileDataRdbAdapter(DAO) | 设备/产品/图标/服务 | 库=`.../profile_data.db`；表 `device_profile`/`product_info`/`device_icon_info`/`service_profile`/`characteristic_profile` | `dp_services_constants.cpp:24`、`profile_data_rdb_adapter.cpp:196` |
| └ 服务信息 | ServiceInfoRdbAdapter | service_info_profile | 库=`.../service_info_store.db`；表 `service_info_profile` | `dp_services_constants.cpp:26`、`service_info_rdb_adapter.cpp:33` |
| └ 本地服务 | LocalServiceInfoRdbAdapter | local_service_info(PIN) | 库=`.../local_service_info_store.db`；表 `local_service_info` | `dp_services_constants.cpp:180`、`local_service_info_rdb_adapter.cpp:33` |
| Asset 加密 | `asset_sdk` | 会话密钥（硬件级） | tag `ALIAS`(=sessionKeyId)/`USER_ID`/`SECRET`/`ACCESSIBILITY`=`SEC_ASSET_ACCESSIBILITY_DEVICE_FIRST_UNLOCKED`；`MAX_SESSIONKEY_SIZE=8192` | `session_key_manager.cpp:46`、`asset_adapter.cpp:28` |

KV 选项（`kv_adapter.cpp:278`）：`createIfMissing=true, encrypt=false, isPublic=true, securityLevel=S1, area=1, kvStoreType=SINGLE_VERSION, autoSync=true, cloudConfig.enableCloud=true`。业务事件 KV 用 `autoSync=false` 且无云配置（本地 KV）。

## 3. KV 键前缀与多用户分发

| 键前缀 | 画像类型 | 单用户格式 | 多用户格式 |
|--------|----------|------------|------------|
| `DEV_` | 设备 | `DEV#<udid>` | 末尾追加 `#<userId>` |
| `SVR_` | 服务 | `SVR#<udid>#<serviceName>` | 末尾追加 `#<userId>` |
| `CHAR_` | 特征 | `CHAR#<udid>#<serviceName>#<characteristicKey>` | 末尾追加 `#<userId>` |
| `SERINFO_` | 服务信息 | `SERINFO#<udid>#<userId>#<serviceId>` | 同（含 userId） |

分隔符 `#`。`DEFAULT_USER_ID = -1`。ServiceInfo 键解析索引：`SERINFO_INDEX=0, UDID_INDEX=1, USERID_INDEX=2, SERVICEID_INDEX=3`（至少 4 段）。

## 4. 核心数据结构

均继承 `DpParcel`（扩展 `Parcelable`），位于 `common/include/interfaces/`。

| 结构体 | 关键字段 | 存储后端 | 头文件 |
|--------|----------|----------|--------|
| `DeviceProfile` | `deviceId_`、`deviceName_`、`manufactureName_`、`deviceModel_`、`storageCapability_`(KB[0..5368709120])、`osSysCap_`、`osApiLevel_`([0..10000])、`osVersion_`、`osType_`(10=OH)、`isMultiUser_`、`userId_`(-1)；RDB 扩展 `id_`/`devType_`/`manu_`/`sn_`/`productId_`/`internalModel_` 等 | KV + RDB `device_profile` | `device_profile.h` |
| `ServiceProfile` | `deviceId_`、`serviceName_`、`serviceType_`、`isMultiUser_`、`userId_` | KV + RDB `service_profile`(外键 `device_profile_id`) | `service_profile.h` |
| `CharacteristicProfile` | `deviceId_`、`serviceName_`、`characteristicKey_`、`characteristicValue_`、`isMultiUser_`、`userId_` | KV + RDB `characteristic_profile` | `characteristic_profile.h` |
| `ServiceInfo` | `udid_`、`userId_`、`displayId_`、`serviceOwnerTokenId_`、`serviceOwnerPkgName_`、`serviceRegisterTokenId_`、`serviceId_`、`timeStamp_`、`publishState_`、`serviceType_`、`serviceName_`、`serviceDisplayName_`、`customData_`、`serviceCode_`、`dataLen_`、`extraData_`、`version_`、`description_` | KV 双层 | `service_info.h` |
| `LocalServiceInfo` | `bundleName_`、`authBoxType_`(-1)、`authType_`(-1)、`pinExchangeType_`(-1)、`pinCode_`、`description_`、`extraInfo_` | RDB `local_service_info` | `local_service_info.h` |
| `ProductInfo` | `productId_`、`model_`、`productName_`、`productShortName_`、`imageVersion_` | RDB `product_info` | `product_info.h` |
| `DeviceIconInfo` | `id_`、`productId_`、`internalModel_`、`subProductId_`、`imageType_`、`specName_`、`version_`、`wiseVersion_`、`url_`、`icon_`(`vector<uint8_t>`，max `MAX_ICON_SIZE=4194304`=4MB)、`modifyTime_` | RDB `device_icon_info` | `device_icon_info.h` |
| `BusinessEvent` | `businessKey_`、`businessValue_` | KV(`BusinessEventAdapter`) | `business_event.h` |
| `DpSyncOptions` | `syncMode_`(默认 `PUSH_PULL`)、`syncDeviceIds_` | 瞬态（API 参数） | `dp_sync_options.h` |
| `SubscribeInfo` | `saId_`(-1)、`subscribeKey_`、`subscribeChangeTypes_`(`unordered_set<ProfileChangeType>`)、`listener_`(`sptr<IRemoteObject>`)；`MAX_SUBSCRIBE_INFO_SIZE=500`；`MAX_SUBSCRIBE_CHANGE_SIZE=6` | RDB `subscribe_trust_info` + 内存 | `dp_subscribe_info.h` |
| `UserInfo`(瞬态) | `udid`、`userId`(-1)、`serviceId`(-1) | 瞬态（查询键） | `user_info.h` |

Trust/ACL 相关结构体见 `trust-acl-access-control.md`。

## 5. 枚举（真实源码值）

来源：`common/include/interfaces/distributed_device_profile_enums.h`。

```cpp
// SyncMode
MIN = -1; PULL = 0; PUSH = 1; PUSH_PULL = 2; MAX = 3

// ProfileChangeType（映射到 IPC 通知码 28-44）
PROFILE_CHANGE_TYPE_MIN = 0
TRUST_DEVICE_PROFILE_ADD = 1; TRUST_DEVICE_PROFILE_UPDATE = 2; TRUST_DEVICE_PROFILE_DELETE = 3
DEVICE_PROFILE_ADD = 4; DEVICE_PROFILE_UPDATE = 5; DEVICE_PROFILE_DELETE = 6
SERVICE_PROFILE_ADD = 7; SERVICE_PROFILE_UPDATE = 8; SERVICE_PROFILE_DELETE = 9
CHAR_PROFILE_ADD = 10; CHAR_PROFILE_UPDATE = 11; CHAR_PROFILE_DELETE = 12
TRUST_DEVICE_PROFILE_ACTIVE = 13; TRUST_DEVICE_PROFILE_INACTIVE = 14
PROFILE_CHANGE_TYPE_MAX = 15

// BindType（非连续范围）
MIN = 0; SAME_ACCOUNT = 1; SHARE = 2; SAME_GROUP = 3
POINT_TO_POINT = 256; COMPATIBLE = 512; DIFF_ACCOUNT = 1282; MAX = 1283

// BindLevel
MIN = 0; USER = 1; SERVICE = 2; APP = 3; MAX = 4

// Status
MIN = -1; INACTIVE = 0; ACTIVE = 1; MAX = 2

// AuthenticationType
MIN = 0; TEMPORARY = 1; PERMANENT = 2; MAX = 3

// DeviceIdType
MIN = 0; UDID = 1; UUID = 2; SN = 3; MAX = 4

// ProfileType（存储级分类）
PROFILE_TYPE_MIN = 0x00; TRUST_DEVICE_PROFILE = 0x10; ACCESS_CONTROL_PROFILE = 0x20
DEVICE_PROFILE = 0x30; SERVICE_PROFILE = 0x40; CHAR_PROFILE = 0x50; PROFILE_TYPE_MAX = 0x60

// ChangeType
CHANGE_TYPE_MIN = 0; ADD = 1; UPDATE = 2; DELETE = 3; CHANGE_TYPE_MAX = 4

// SyncStatus
SUCCEEDED = 0; FAILED = 1

// SwitchFlag
SWITCH_FLAG_MIN = -1
SWITCH_FLAG_KEY_MOUSE_EDGE_CROSSING = 0; SWITCH_FLAG_KEY_DISTRIBUTED_PASTEBOARD = 1
SWITCH_FLAG_DCSHARESWITCH = 2; SWITCH_FLAG_WIFI_DISPLAY_SERVICE = 3
SWITCH_FLAG_DISTRIBUTED_SUPER_MANAGER = 4; SWITCH_FLAG_MAX = 5

// StaticCapabilityFlag
CAPABILITY_FLAG_MIN = -1; CAPABILITY_FLAG_DMS = 0; CAPABILITY_FLAG_PASTE_BOARD = 1
CAPABILITY_FLAG_DISTRIBUTED_FILE_DAEMON = 2; CAPABILITY_FLAG_MAX = 3
```

`ProfileEvent`（高层通知事件）：`EVENT_PROFILE_CHANGED`→`IProfileChangeListener::OnProfileChange`；`EVENT_SYNC_COMPLETED`→`ISyncCompletedCallback::OnSyncCompleted`；`EVENT_DEVICE_PROFILE_INITED`→`IDpInitedCallback::OnDpInited`；`EVENT_PINCODE_INVALID`→`IPinCodeInvalidCallback::OnPinCodeInvalid`。

## 6. 错误码（真实头文件常量）

来源：`common/include/constants/distributed_device_profile_errors.h`，基址 `98566143`。**文档旧名与头文件名/值不一致**（如旧文档 `DP_PERMISSION_DENIED=98566144`，实际 `DP_PERMISSION_DENIED=98566155`，`98566144` 实为 `DP_INVALID_PARAMS`）。**以本表（头文件为准）**。仅列高频码，完整清单见头文件。

| 错误码 | 数值 | 含义 |
|--------|------|------|
| `DP_SUCCESS` | 0 | 成功 |
| `DP_INVALID_PARAMS` | 98566144 | 参数无效 |
| `DP_INTERFACE_CHECK_FAILED` | 98566145 | 接口令牌校验失败（Stub `OnRemoteRequest`） |
| `DP_GET_LOCAL_UDID_FAILED` | 98566146 | 获取本端 UDID 失败 |
| `DP_GET_SERVICE_FAILED` | 98566147 | 获取 SA 失败（客户端取不到 dpService） |
| `DP_INIT_DB_FAILED` | 98566148 | 数据库初始化失败 |
| `DP_PERMISSION_DENIED` | 98566155 | 权限被拒绝 |
| `DP_NOT_INIT_DB` | 98566157 | 数据库未初始化 |
| `DP_LOAD_SERVICE_ERR` | 98566160 | SA 未加载/未初始化（Stub `!IsInited()`） |
| `DP_CACHE_EXIST` | 98566164 | 缓存已存在 |
| `DP_PUT_ACL_PROFILE_FAIL` | 98566170 | 写 ACL 失败 |
| `DP_GET_ALL_TRUST_DEVICE_PROFILE_FAIL` | 98566169 | 获取所有可信设备失败 |
| `DP_UPDATE_ACL_PROFILE_FAIL` | 98566171 | 更新 ACL 失败 |
| `DP_CONTENT_SENSOR_MANAGER_INIT_FAIL` | 98566179 | 内容传感器初始化失败 |
| `DP_PUT_KV_DB_FAIL` | 98566197 | KV 写入失败 |
| `DP_DEL_KV_DB_FAIL` | 98566198 | KV 删除失败 |
| `DP_GET_KV_DB_FAIL` | 98566199 | KV 查询失败 |
| `DP_KV_SYNC_FAIL` | 98566204 | KV 同步失败 |
| `DP_NOT_FIND_DATA` | 98566221 | 找不到数据 |
| `DP_WRITE_PARCEL_FAIL` | 98566235 | IPC 写入失败 |
| `DP_READ_PARCEL_FAIL` | 98566236 | IPC 读取失败 |
| `DP_INVALID_PARAM` | 98566245 | 删除非本地设备等（Profile CRUD） |
| `DP_LOAD_SYNC_ADAPTER_FAILED` | 98566248 | Sync Adapter 库加载失败（非 OH） |
| `DP_UPDATE_ACL_NOT_ALLOW` | 98566249 | 更新 ACL 不可变字段 |
| `DP_DATA_EXISTS` | 98566253 | 重复 ACL |
| `DP_STATIC_COLLECT_FAIL` | 98566254 | 静态能力采集失败 |
| `DP_LOCAL_SERVICE_INFO_EXISTS` | 98566325 | 本地服务信息重复 |
| `DP_SERVICE_ON_IDLE` | 98566330 | SA 空闲（Stub `ExitIdleState` 失败，瞬态，客户端重试） |
| `DP_SERVICE_STOPPED` | 98566331 | 服务已停止（Stub `IsStopped`，瞬态，客户端重试） |

客户端重试集合 `retryErrCodes_ = { DP_SERVICE_STOPPED, DP_LOAD_SERVICE_ERR, DP_ERR_DEAD_OBJECT, DP_BR_DEAD_REPLY }`（后两者为 IPC 框架码，非本头文件）。

## 7. 多用户隔离规则

| 规则 | 说明 | 锚点 |
|------|------|------|
| 前台用户校验 | 读取画像前 `IsMultiUserValid` 检查 `userId` 是否为前台用户 | `device_profile_manager.cpp:1125` |
| 失败返回 | 非前台用户读返回 `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID`(98566279) | 同上 |
| 键后缀 | 多用户画像键末尾追加 `#<userId>`；单用户 `DEFAULT_USER_ID=-1` 不追加 | `MultiUserManager` |
| 删除本地约束 | `DeleteServiceProfile`/`DeleteCharacteristicProfile` 校验 `IsLocalUdid(deviceId)`，非本地返回 `DP_INVALID_PARAM`(98566245) | `profile_control_utils.cpp` |
| 用户删除级联 | `DeleteRemovedUserData(userId)` 级联清理该用户画像 | `DeviceProfileManager` |
| 公共事件 | 监听 `COMMON_EVENT_USER_SWITCHED`/`COMMON_EVENT_USER_REMOVED` | `multi_user_manager.cpp`、`dp_account_common_event.cpp` |

## 8. 常见误用

| 误用 | 后果 | 修正 |
|------|------|------|
| 用旧文档错误码值（如 `DP_PERMISSION_DENIED=98566144`）排查 | 误判：98566144 实为 `DP_INVALID_PARAMS`，权限拒绝实为 98566155 | 以 `distributed_device_profile_errors.h` 头文件为准 |
| 手工拼 KV 键不加分隔符 `#` 或漏 `userId` 后缀 | 键不匹配，查询返回 `DP_NOT_FIND_DATA`(98566221) 或写入到错误命名空间 | 用 `ProfileUtils::DeviceProfileToEntries` 等序列化工具构造键 |
| 多用户模式下用单用户键读写 | 数据落到默认用户命名空间，前台用户读不到 | 代理已序列化 `isMultiUser`+`userId`，调用方须正确传入 |
| 删除非本地设备的 Service/CharProfile | 返回 `DP_INVALID_PARAM`(98566245) | 删除前 `IsLocalUdid` 校验；只能删本地设备画像 |
| 业务事件用非白名单 `businessKey` | 返回 `DP_INVALID_PARAM`(98566245) | 仅 `DP_REJECT_KEY`/`DP_DISTURBANCE_KEY` 受支持 |
| 设 `icon` 超过 4MB | 写入失败 | `MAX_ICON_SIZE=4194304`，前置校验 |
| `sessionKey` 超过 8192 字节 | 返回 `DP_INVALID_PARAMS`(98566144) | `MAX_SESSIONKEY_SIZE=8192`，前置校验 |

## 9. 反模式 / 修改前检查

- 新增画像类型必须同时更新：数据结构头文件、`ProfileUtils` 键构造/解析、`KVAdapter`/`RdbAdapter` schema、`ProfileType` 枚举、`ProfileChangeType` 枚举、订阅分发 `funcsMap_`、采集器（若需采集）、错误码。漏改即出现读写不一致或通知不触发。
- 修改 KV storeId 或 appId 必须同步 `kv_adapter.cpp` 选项与数据库目录权限（`deviceprofile.cfg` 的 mkdir）；改错会导致 KV 打不开返回 `DP_KV_DB_INIT_FAIL`(98566190)。
- 修改 RDB schema（新增表/字段/索引）必须升级 `RDB_VERSION` 并在 `OpenCallback` 写迁移 SQL；不升级导致旧库不迁移、读列失败。
- 不允许直接读写 `KvStore`/`RdbStore` 绕过适配器；统一经 `KvAdapter`/`RdbAdapter` 以保证监听器与死亡恢复生效。
- 新增错误码必须在 `distributed_device_profile_errors.h` 连续编号，并同步 README/接口文档错误表与 `docs/06-debugging`（legacy）排查表。

## 10. 测试指引

- 数据结构与序列化：`common/test/device_profile_test.cpp`、`service_info_test.cpp`、`profile_change_listener_stub_test.cpp`。
- Profile CRUD：`device_profile_manager_*_test.cpp`（目标 `device_profile_manager_new_test`/`_new_two_test`/`_new_three_test`）、`profile_control_utils_test.cpp`、`profile_utils_new_test`、`profile_cache_new_test`。
- 适配器：`kv_adapter_new_test.cpp`、`rdb_adapter_new_test.cpp`、`service_info_kv_adapter_test.cpp`、`business_event_adapter_test.cpp`、`switch_adapter_test`。
- DAO：`device_profile_dao_test`、`product_info_dao_test`。
- 多用户：`multi_user_manager_test`。
- 完整清单与命令见 `../03-build-test.md`。
