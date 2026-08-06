# 信任与访问控制知识

> 本文只记录 DP 的信任设备、访问控制（ACL）、Accesser/Accessee 概念、4 表 RDB 模型、级联删除、LNN ACL 与权限模型。
> 服务分层与 SA 生命周期见 `service-architecture.md`；画像数据结构与存储后端见 `profile-data-and-storage.md`；同步与订阅通知见 `sync-subscription-notification.md`。
> ACL 写入/删除的**严格级联时序**见 `../01-workflows.md` 第 4-5 节。

## 1. 概念模型

**ACL 连接 Accesser 与 Accessee：** 设备 A（发起方）创建 `Accesser`，设备 B（目标方）创建 `Accessee`，一个 `AccessControlProfile` 将二者关联，并附带 `trustDeviceId`、`bindType`、`bindLevel`。

| 角色 | 含义 | 主键 | 关键字段 | 表 |
|------|------|------|----------|----|
| Accesser | 信任关系发起方（谁发起访问） | `accesserId`（自增） | `accesserDeviceId_`/`accesserUserId_`/`accesserBundleName_`/`accesserTokenId_`/`accesserAccountId_`/`accesserDeviceName_` | `accesser_table` |
| Accessee | 信任关系目标方（谁授予访问） | `accesseeId`（自增） | 与 Accesser 对称（前缀 `accessee`） | `accessee_table` |
| AccessControlProfile | ACL 条目 | `accessControlId`（自增） | `accesserId_`/`accesseeId_`/`trustDeviceId_`/`bindType_`/`bindLevel_`/`status_`/`authenticationType_`/`extraData_` | `access_control_table` |
| TrustDeviceProfile | 远端设备持久化信任关系 | `deviceId` | `deviceIdType_`(UDID/UUID/SN)/`status_`(INACTIVE/ACTIVE)/`bindType_`/`peerUserId_`/`localUserId_` | `trust_device_table` |

`AccessControlProfile`/`Accesser`/`Accessee`/`TrustDeviceProfile` 均位于 `common/include/interfaces/`，继承 `DpParcel`。

## 2. 4 表 RDB 模型

库：`.../acl_db/dp_rdb.db`，version `RDB_VERSION_5_1_2=3`，由 `RdbAdapter` 包装 `native_rdb`。锚点：`rdb_adapter.cpp:29`、`trust_profile_manager.h:156`、`dp_constants.cpp:247`。

| 表 | 唯一键 | 说明 |
|----|--------|------|
| `trust_device_table` | `deviceId` | 每设备一行；status 聚合自其下所有 ACL |
| `access_control_table` | `(accesserId, accesseeId, trustDeviceId)` | 一条 ACL |
| `accesser_table` | `(accesserId, accesserUserId, accesserTokenId)` 或 `(accesserId, accesserUserId, accesserBundleName)` 或 `(accesserId, accesserUserId, accesserAccountId)` | 访问发起方，可被多条 ACL 引用 |
| `accessee_table` | 与 accesser 对称 | 访问目标方 |
| `subscribe_trust_info_table` | — | 订阅信任信息（供跨设备转发） |

外键关系：`access_control.accesserId → accesser.accesserId`；`access_control.accesseeId → accessee.accesseeId`；`access_control.trustDeviceId → trust_device.deviceId`。删除信任设备级联清理其下 accesser/accessee/access_control。

## 3. ACL 写入流程（阶段表）

> 严格时序与违反后果见 `../01-workflows.md` 第 4 节。本表只列阶段与锚点。

| 阶段 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| 入口 | `PutAccessControlProfile` (StubNew) | `PutAccessControlProfileInner` | `services/core/src/distributed_device_profile_service_new.cpp` |
| 可信校验 | `PermissionManager::IsCallerTrust(PUT_ACCESS_CONTROL_PROFILE)` | `IsCallerTrust` | `services/core/src/permissionmanager/permission_manager.cpp` |
| 路由 | `TrustProfileManager::PutAccessControlProfile` | `PutAccessControlProfile` | `services/core/src/trustprofilemanager/trust_profile_manager.cpp:111` |
| 扫描匹配 | `CheckDeviceIdAndUserIdExists` | `:2010` | 同上 |
| 分配 ID | `SetAccessControlProfileId` | `:1619` | 同上 |
| 写 accesser | `PutAccesserProfile`（INSERT 或 NOOP） | `:1183` | 同上 |
| 写 accessee | `PutAccesseeProfile`（INSERT 或 NOOP） | `:1226` | 同上 |
| 重复检测 | `IsAclExists`（除 status 外字段比较） | `:1947` | 同上 |
| 插 ACL | INSERT `access_control_table` | 同上 | 同上 |
| trust 级联 | `PutAclCheck` | `:1906` | 同上 |
| 信任通知 | 不存在→`NotifyTrustDeviceProfileAdd`；已存在→`GetResultStatus` 聚合 UPDATE | `:1450` | 同上 |
| 通知 DM | `DpAclAdd(accessControlId, trustDeviceId, bindType)` | 同上 | 同上 |

## 4. ACL 删除四级级联（阶段表）

> 严格时序见 `../01-workflows.md` 第 5 节。级联顺序：accessee → accesser → ACL 记录 → trust_device，依赖 COUNT 引用计数。

| 阶段 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| 入口 | `DeleteAccessControlProfile(accessControlId)` | (Svc) `:489` | `.../distributed_device_profile_service_new.cpp` |
| 查询待删 | `TrustProfileManager::DeleteAccessControlProfile` → SELECT | `:741` | `trust_profile_manager.cpp` |
| 级联入口 | `DeleteAccessControlProfileCheck` | `:1564` | 同上 |
| 阶段一 | `DeleteAccesseeCheck`（COUNT==1 才删） | `:2089` | 同上 |
| 阶段二 | `DeleteAccesserCheck`（COUNT==1 才删） | `:1840` | 同上 |
| 阶段三 | DELETE `access_control_table` WHERE accessControlId | 同上 | 同上 |
| 阶段四 | `DeleteTrustDeviceCheck` | `:2127` | 同上 |
| 复查 | `CheckDeviceIdAndUserIdExists` | `:2010` | 同上 |
| 无引用且非 LNN | `NotifyTrustDeviceProfileDelete` + DELETE/UPDATE `trust_device_table` | `:1450` | 同上 |

## 5. 双向查询路由

| 步骤 | 操作 | 代码锚点 | 源码路径 |
|------|------|----------|----------|
| 入口 | `GetAccessControlProfile(params map)` | `:305` | `trust_profile_manager.cpp` |
| 生成查询 | `GenerateQueryProfile` | `:947` | 同上 |
| 正向 | `CheckForWardByAcerAndAcee` | `:841` | 同上 |
| 逆向 | `CheckReverseByAcerAndAcee` | `:894` | 同上 |
| LNN 过滤 | `RemoveLnnAcl` / `IsLnnAcl` | `:2165` / `:2178` | 同上 |

## 6. LNN ACL 与用户绑定 ACL

| 概念 | 来源 | `GetAllAccessControlProfile` 包含 | `GetAllAclIncludeLnnAcl` 包含 |
|------|------|-----------------------------------|-------------------------------|
| 用户绑定 ACL | 显式用户操作（设备绑定、账号关联） | 是 | 是 |
| LNN ACL | 同一局域网自动发现（SoftBus LNN 协商） | 否（被 `RemoveLnnAcl` 过滤） | 是 |

`GetAllAclIncludeLnnAcl` 接口码 `66`，与 `GetAllAccessControlProfile`(12) 的唯一区别是是否包含 LNN 临时信任。

## 7. 权限模型

`PermissionManager::IsCallerTrust(interfaceName)` / `CheckCallerPermission()` 在每个外部 API 入口调用。`GetCallerProcName()` 经 `access_token:libaccesstoken_sdk` 的 `GetNativeTokenInfo(callingPid, ...)` 从 IPC 上下文取调用进程名，再与 `permissionMap_[interfaceName]` 比对：`permissionMap_[name].count(procName) > 0 || permissionMap_[name].count("all") > 0`。`permissionMap_` 在 `PermissionManager::Init()` 经 `config_policy` 的 `GetCfgFiles("deviceprofile/permission.json")` 定位并 cJSON 解析加载。加载失败→`permissionMap_` 为空→所有受保护 API 被拒。

锚点：`permission_manager.cpp`、`permission/permission.json`（`ohos_prebuilt_etc("permission_json")` 安装到 `deviceprofile/`）。

| 接口分组 | 允许的 caller 进程 |
|----------|---------------------|
| ACL 读写（`Put/Update/Delete/Get/GetAll` TrustDeviceProfile 与 ACL）、会话密钥 | `device_manager`、`softbus_server` |
| `GetAccessControlProfile` | `device_manager`、`softbus_server`、`iShare` |
| `PutAllTrustedDevices`、设备/产品/图标批量、本地服务信息、ServiceInfo | `device_manager` |
| `Put/Get/Delete` Service/CharProfile、`GetDeviceProfile`、订阅、`SyncDeviceProfile` | `all` |
| `SubscribeDeviceProfileInited`/`UnSubscribeDeviceProfileInited`、`SubscribePinCodeInvalid`、`SyncStaticProfile`、`SendSubscribeInfos`、业务事件、`SubscribeAllServiceInfo` | 开放（不在 `permission.json`） |

## 8. 线程安全

| 锁 | 保护对象 | 位置 |
|----|----------|------|
| `subscribeMutex_` | `subscribeInfoMap_`（订阅容量检查与擦写） | `subscribe_profile_manager.cpp` |
| `storeMutex_` / `syncStoreMutex_` | ServiceInfo 双层 KV 写入 | `service_info_manager.cpp` |
| `pinCodeCallbackMapMtx_` | `pinCodeCallbackMap_` | `distributed_device_profile_service_new.cpp` |
| `businessEventCallbackMapMtx_` | `businessEventCallbackMap_` | 同上 |
| `dpInitedCallbackMap_` 守卫 | `dpInitedCallbackMap_` | 同上 |
| `dynamicStoreMutex_` | BusinessEvent KV 写入 | `business_event_manager.cpp` |

> 注意：`businessEventCallbackMap_` **无自动死亡接收者清理**，已失效条目保留直到显式注销。

## 9. 常见误用

| 误用 | 后果 | 修正 |
|------|------|------|
| 更新 ACL 不可变字段（`accesserId`/`accesseeId` 等） | 返回 `DP_UPDATE_ACL_NOT_ALLOW`(98566249) | 仅可改 status 等可变字段；不可变字段须删后重建 |
| 插入重复 ACL | 返回 `DP_DATA_EXISTS`(98566253) | `IsAclExists` 已检测，调用方应先查再插 |
| 调用方不在 `PUT_ACCESS_CONTROL_PROFILE` 白名单 | 返回 `DP_PERMISSION_DENIED`(98566155) | 仅 `device_manager`/`softbus_server` 可写 ACL |
| 调用方不在 `PUT_SESSION_KEY` 白名单 | 返回 `DP_PERMISSION_DENIED`(98566155) | 仅 `device_manager`/`softbus_server` 可写会话密钥 |
| `permission.json` 解析失败 | `permissionMap_` 为空，所有受保护 API 全部被拒 | 检查配置路径与 JSON 合法性；失败码 `DP_PARSE_PERMISSION_JSON_FAIL`(98566207) |
| 期望 `GetAllAccessControlProfile` 返回 LNN ACL | 拿不到 LNN 临时信任 | 用 `GetAllAclIncludeLnnAcl`(接口码 66) |
| 删除 ACL 时跳过级联 | accesser/accessee/trust_device 残留孤儿行 | 必须走 `DeleteAccessControlProfileCheck` 四级级联 |
| 用 `PutAccessControlProfile` 写非信任设备 | `IsCallerTrust` 校验失败被拒 | 信任/会话密钥接口须受信调用方，不开放给 `all` |

## 10. 反模式 / 修改前检查

- 新增 ACL 字段必须同步：`AccessControlProfile` 头、`access_control_table` schema 与 `RDB_VERSION` 迁移、`IsAclExists` 重复检测字段集、双向查询 `GenerateQueryProfile`、权限白名单（若需受信）。漏改即出现重复检测失效或查询漏字段。
- 修改级联顺序前必须确认引用计数 COUNT 语义；改错会导致 trust_device 被误删或残留。
- 不允许直接操作 `RdbStore` 绕过 `TrustProfileManager`；统一经 `RdbAdapter` 以保证级联与通知。
- 新增受保护接口必须在 `permission.json` 加白名单条目，否则 `IsCallerTrust` 永远拒绝。
- 修改 `bindType`/`bindLevel` 枚举值须同步 `BindType`/`BindLevel` 枚举与 ACL 校验范围；值不连续（`[1-3]` 与 `[256,512,1282]`），勿手工推算。

## 11. 测试指引

- Trust/ACL：`trust_profile_manager_test.cpp`（目标 `TrustProfileManagerTest`）、`trust_profile_manager_two_test`、`trust_Device_Profile_test`、`trustprofilemanager_fuzzer`（`TrustProfileFuzzTest`）。
- 会话密钥：`session_key_manager_test.cpp`、`asset_adapter`（经 `session_key_manager_test` 间接覆盖）。
- 权限：`permission_manager_test.cpp`（`PermissionManagerTest`）。
- 本地服务/PIN：`local_service_info_manager_test`、`local_service_info_rdb_adapter`（经 manager 测试覆盖）。
- Stub 派发：`distributed_device_profile_stub_new_test.cpp`。
- 完整清单与命令见 `../03-build-test.md`。
