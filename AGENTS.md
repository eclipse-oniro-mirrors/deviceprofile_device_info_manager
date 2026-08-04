# deviceprofile_device_info_manager 指引

> 部件 `@ohos/device_info_manager` | subsystem `deviceprofile` | SAID 6001 | 进程 `deviceprofile`
> 本文件是知识库入口。先在下表找到你的场景，读对应文档，再动手改代码。

## 项目定位

`deviceprofile_device_info_manager` 是 OpenHarmony 分布式设备画像的**集中式存储与同步管理层**，作为分布式系统中设备硬件能力、系统软件特征和信任关系信息的唯一权威数据源。以系统服务 SAID 6001（进程 `deviceprofile`）运行，对外提供设备/服务/特征画像存取、信任与访问控制管理、跨设备同步、变更订阅，并以 KV / RDB / Asset 三种后端持久化。

**它是：** 一个持久化画像仓库 + 一个数据同步引擎 + 一个变更通知中心。
**它不是：** 通信传输层（委托 SoftBus 与 DeviceManager）、认证授权服务（认证由 device_auth 处理）、编排引擎。

优先按这些目录定位问题：

| 目录 | 作用 |
|------|------|
| `services/core/` | 服务核心：SA 生命周期（`DistributedDeviceProfileServiceNew`）、所有 Manager、持久化适配器、采集器、DFX |
| `common/` | 共享层：`DpParcel` 数据结构、IPC broker/stub/proxy、常量与枚举、日志宏 |
| `interfaces/innerkits/core/` | 客户端 SDK：`DistributedDeviceProfileClient`、`DistributedDeviceProfileProxy`、SA 装载回调 |
| `permission/permission.json` | 调用方进程→可调用接口的白名单（权限模型唯一数据源） |
| `radar/` | DFX Radar 上报：`DpRadarHelper` 单例（`SUBSYS_DISTRIBUTEDHARDWARE_DP=205`），各业务场景上报点 |
| `sa_profile/6001.json` | SA 配置：SAID 6001 注册声明（`BUILD.gn` 引用） |
| `etc/init/deviceprofile.cfg` | 进程配置：`uid=dms`/`gid=dms,shell`/`secon`、数据库目录 mkdir、延迟卸载 |

## 构建和验证

构建命令在 **OpenHarmony 源码根目录**运行（非本子仓目录），用 GN + Ninja。根构建目标、测试目标、变更验证矩阵、feature flag、板级验证证据模板见 `docs/03-build-test.md`。常用命令速查：

```bash
# 在 OH 源码根目录构建
./build.sh --product-name <product> --build-target deviceprofile_device_info_manager
# 单测
./build.sh --product-name <product> --build-target tests --gn-args is_notertest=true
# 板侧日志/调试（见 docs/02-verification.md）
hdc shell hilog -T DHDP
hdc shell hidumper -s 6001
```

特殊说明：`deviceprofile.gni` 设 `build_flags = ["-Werror"]`（警告即错误）；旧文档错误码值与头文件不一致，**一律以 `common/include/constants/distributed_device_profile_errors.h` 头文件为准**。

### 完成定义（Done）

变更完成前须满足（完整版见 `docs/03-build-test.md` 第 8 节）：

1. `services/core:unittest`、`common:test`、`radar:test`、`fuzztest` 四组全绿，无新 `-Werror` 警告。
2. 按变更类型完成 `docs/03-build-test.md` 第 3-4 节的最低检查项与最低证据。
3. 板级验证证据齐全（`docs/03-build-test.md` 第 5.4 节模板），无 `DP_SYNC_FAILED`/`DP_PERMISSION_DENIED`/`DP_LOAD_SERVICE_ERR` 异常码。
4. 接口/错误码/枚举与源码头文件一致（不手工推算数值）。
5. 若改了接口码、schema、权限、feature flag，已同步本知识库对应文档。

### 无法运行验证时的回退

若环境受限无法执行构建/单测/板级验证：

1. 在 PR 描述中标注「**验证待补**」并说明受限原因（无设备/无编译环境/无板）。
2. 列出已完成的静态自查项（代码审查、约束对照、锚点核对）。
3. 标记需人工验证的变更类型与风险等级。
4. 不得在未标注「验证待补」的情况下合并代码。

## 知识索引

| 场景（我想做什么） | 先读 |
|--------------------|------|
| 理解服务分层 / SA 6001 生命周期 / Manager 矩阵 / IPC 派发 | `docs/knowledge/service-architecture.md` |
| 理解画像三层层级 / 数据结构 / KV-RDB-Asset 后端 / 键前缀 / 多用户 / 枚举 / 错误码 | `docs/knowledge/profile-data-and-storage.md` |
| 理解信任 / ACL / Accesser-Accessee / 4 表级联 / LNN / 权限模型 | `docs/knowledge/trust-acl-access-control.md` |
| 理解跨设备同步（OH KV / 非 OH Adapter / E2E）/ 订阅与通知链 / 回调 stub-proxy | `docs/knowledge/sync-subscription-notification.md` |
| 改启动/关停/CRUD/ACL/同步/订阅/采集等流程的时序 | `docs/01-workflows.md` |
| 排查问题 / 查日志 / 查错误码 / HiSysEvent / Radar | `docs/02-verification.md` |
| 构建目标 / 单测 fuzz 目标 / 变更验证矩阵 / 板级验证 / feature flag | `docs/03-build-test.md` |
| 新增或修改 IPC 接口码 | 本文件「接口码约束」+ `docs/knowledge/service-architecture.md` 第 4 节 |
| 新增错误码 | `docs/knowledge/profile-data-and-storage.md` 第 6 节 + README 错误表 |
| 改 KV/RDB schema | `docs/knowledge/profile-data-and-storage.md` 第 2 节 + `docs/03-build-test.md` 第 4 节 |
| 改同步或订阅 | `docs/knowledge/sync-subscription-notification.md` + `docs/01-workflows.md` 第 8-11 节 |

### 词汇路由

遇到以下术语/缩写时，先读对应文档再动手：

| 术语 / 缩写 | 含义 | 先读 |
|-------------|------|------|
| ACL / Accesser / Accessee / trust_device | 信任关系与访问控制四表模型 | `docs/knowledge/trust-acl-access-control.md` |
| LNN / `GetAllAclIncludeLnnAcl` | LNN 类型 ACL 与普通 ACL 的差异 | `docs/knowledge/trust-acl-access-control.md` |
| storeId / KV 前缀 / RDB schema | 画像键前缀、storeId 分配、表结构 | `docs/knowledge/profile-data-and-storage.md` 第 2 节 |
| `aclAndSubscribeFuncs_` / `isInited_` / `PostInit` | SA 初始化门控与临时缓存机制 | `docs/knowledge/service-architecture.md` 第 4-5 节 |
| E2ESync / PUSH_PULL / `IDPSyncAdapter` | 跨设备同步模式与非 OH 适配器 | `docs/knowledge/sync-subscription-notification.md` |
| `DBKeyToSubcribeKey` / `ProfileChangeType` | 订阅键映射与变更通知链 | `docs/knowledge/sync-subscription-notification.md` |
| `depSaIds_` / 5 依赖 SA | SA 启动依赖与就绪判定 | `docs/01-workflows.md` 第 1 节 |
| `permission.json` / `IsCallerTrust` / `CheckCallerPermission` | 权限模型与白名单 | 本文件「Clean Code 规范」+ `docs/knowledge/service-architecture.md` |
| Asset / `SessionKeyManager` | Asset 加密存储与会话密钥 | `docs/01-workflows.md` 第 16 节 |
| feature flag / `deviceprofile.gni` | 编译开关与条件编译宏 | `docs/03-build-test.md` 第 6 节 |

### 编辑前声明

动手改代码前，须先声明以下三项：

1. **任务类型**：接口变更 / Manager 变更 / 存储变更 / 同步变更 / 订阅变更 / 权限变更 / feature flag 变更 / 新增采集器。
2. **已读文档**：按「知识索引」和「词汇路由」确定的本任务必读文档。
3. **已识别约束**：本文件「开发约束」中与任务相关的约束（含违反后果）。

> 旧版学术式文档已归档至 `docs/_legacy/`（含 `knowledge.md` 旧 hub、architecture/concepts/data-structures、9 个 workflow、3 个 interface 文档等），仅供追溯，不再维护。

## 开发约束

### Ask before（须升级审批的变更）

以下变更须先与 CODEOWNERS 确认，不得擅自合入：

| 变更项 | 原因 | 审批依据 |
|--------|------|----------|
| 改 `permission/permission.json` 白名单 | 权限模型唯一数据源，误改导致越权或拒权 | 本文件「Clean Code 规范」access token 检查 |
| 改 `depSaIds_` 依赖 SA 集合 | 影响 `PostInit` 触发条件，遗漏依赖导致初始化不完成 | 本文件「时序约束」SA 启动时序 |
| 改 `deviceprofile.gni` 开关默认值 | 影响形态产物与条件编译分支 | `docs/03-build-test.md` 第 6 节 |
| 改 `common/BUILD.gn` 的 `idl_gen_interface` | IDL 生成代码是回调 stub/proxy 的源头，手改会被覆盖 | 本文件「接口码约束」第 5 项 |
| 改 `aclAndSubscribeFuncs_` 集合 | 控制初始化门控绕过，误加导致未初始化写入 | 本文件「接口码约束」注意段 |
| 改 KV storeId 或 RDB 表结构 | 持久化格式变更涉及迁移与跨版本兼容 | `docs/03-build-test.md` 第 3 节存储行 |

### 架构约束

- **四层分层**：Client SDK（`interfaces/innerkits/core/`）→ IPC Transport（`common/`）→ Service Core（`services/core/`）→ Storage Backends（适配器）。新能力按职责落到对应层：外部 API 入口落 SDK/IPC；业务逻辑落 Manager；持久化落适配器。违反层级会导致循环依赖或监听器失效。
- **新增 Manager** 必须在 `Init()`/`PostInit()`/`PostInitNext()` 之一注册、在 `UnInit()`/`UnInitNext()` 逆序反初始化；未注册则不会被初始化。违反：Manager 不可用、空指针。
- **单例**：一律用 `XxxManager::GetInstance()`（`IMPLEMENT_SINGLE_INSTANCE`）；**不要** `new`，也不要假设 `DelayedSpSingleton`（本仓未使用）。违反：多实例状态不一致、锁失效。
- **feature flag 集中管理**：编译开关统一定义在 `deviceprofile.gni`（`device_info_manager_supported_switch`/`device_info_manager_capability`/`device_info_manager_adaptation_watch`/`dp_os_account_part_exists`/`device_info_manager_common`），并在 `BUILD.gn` 转为条件编译宏（`DEVICE_PROFILE_SWITCH_DISABLE`/`DEVICE_PROFILE_STATIC_DISABLE`/`DP_OS_ACCOUNT_PART_EXISTS`/`WATCH_SUPPORT`）。不在源码内硬编码开关。违反：形态切换后功能错乱或产物未产出。
- **SA 生命周期清晰**：`OnStart`→`Init`→注册 5 依赖 SA 监听→`Publish`→延迟卸载；`OnStop`→逆序 `UnInit`。改 `depSaIds_` 须同步 `OnAddSystemAbility` 分支，否则依赖 SA 上线无法触发 `PostInit`。

### Clean Code 规范

- **作用域纪律**：受保护接口经 `PermissionManager::IsCallerTrust`/`CheckCallerPermission`；不在内部 Manager 暴露未鉴权入口。违反：越权调用。
- **头文件暴露**：内部头不出 `inner_kits`；`inner_kits` 仅暴露 `distributed_device_profile_client.h`/`distributed_device_profile_proxy.h` 与 common 数据结构头。违反：调用方依赖内部实现。
- **RAII / 资源守卫**：KV `ResultSet`/Asset 结果集用完即 `FreeResultSet`；线程用 `join` 或 detach 明确；锁用 `std::lock_guard`。违反：资源泄漏或死锁。
- **IPC 返回值检查**：Proxy `SEND_REQUEST` 后检查返回码，序列化失败返回 `DP_WRITE_PARCEL_FAIL`(98566235)/`DP_READ_PARCEL_FAIL`(98566236)。违反：静默失败。
- **日志隐私**：按 OpenHarmony 隐私规范使用 `%{private}`/`%{public}`；不打印 UDID/密钥明文。
- **错误码复用**：优先复用头文件已有错误码；新增须连续编号且同步文档。不手工推算数值。
- **access token 检查**：调用方身份经 `access_token:libaccesstoken_sdk` 的 `GetNativeTokenInfo(callingPid, ...)` 取进程名，与 `permission.json` 比对。不在 Manager 内重新实现鉴权。
- **异步生命周期**：回调派发经 `EventHandler->PostTask` 异步；回调方向码由回调 stub 处理，不进主 Stub `OnRemoteRequest`。注意 `businessEventCallbackMap_` 无死亡接收者，须显式注销。
- **内存 / BUILD 边界**：进程 `uid=dms`/`gid=dms,shell`/`secon=u:r:distributedsche:s0`；数据库目录权限见 `etc/init/deviceprofile.cfg`。改 storeId 须同步 mkdir。
- **格式合规**：`build_flags = ["-Werror"]`，代码须无警告。

### 接口码约束

修改 `IDistributedDeviceProfile` 接口或接口码时，**六端必须同步**，任一缺失即 IPC 路由错配或鉴权失败：

1. `common/include/interfaces/dp_ipc_interface_code.h` — 接口码枚举
2. `services/core/src/distributed_device_profile_stub_new.cpp` — `OnRemoteRequest` 派发表与 `aclAndSubscribeFuncs_` 集合
3. `interfaces/innerkits/core/src/distributed_device_profile_proxy.cpp` — `SEND_REQUEST` 码
4. `permission/permission.json` — 若需受信，加白名单条目
5. 回调方向：若为回调，新增/修改对应回调 stub/proxy（`common/include/interfaces/` 与 `common/src/interfaces/`），IDL 回调经 `common/BUILD.gn` 的 `idl_gen_interface` 生成
6. 测试与 mock：`distributed_device_profile_stub_new_test`、对应 Manager 单测、`all_interface_fuzzer`/`high_risk_interface_fuzzer`

> 注意 `aclAndSubscribeFuncs_`（36 个码：`7,8,9,10,11,12,13,66,23,24,26,14,15,16,17,41,42,45,46,47,51,48,49,50,55,56,57,58,60,61,77,52,53,54,73,78`）绕过 `IsInited` 检查，可在 `PostInit` 完成前调用（数据落临时缓存）。新增"写类/订阅类"接口码须评估是否加入该集合。

### 时序约束

> 完整时序见 `docs/01-workflows.md`。以下为不可违反的关键规则。

- **SA 启动时序**：必须先 `Init`（5 基础 Manager）→ 注册 5 依赖 SA 监听 + `Publish` → 依赖 SA 全上线 → `PostInit`（9 Manager）→ `PostInitNext`（3 Manager + 刷临时缓存 + `isInited_=true` + `NotifyDeviceProfileInited`）。违反：在 `PostInit` 完成前调读取类接口返回 `DP_LOAD_SERVICE_ERR`(98566160)；临时缓存未刷新则写入数据丢失。
- **SA 关停时序**：`UnInit`/`UnInitNext` 必须与 `Init`/`PostInit`/`PostInitNext` 相反。违反：悬空访问或锁失效；`OnStop` 后 IPC 返回 `DP_SERVICE_STOPPED`(98566331)。
- **ACL 删除级联**：必须按 accessee → accesser → ACL 记录 → trust_device 四级，依赖 COUNT 引用计数。违反：残留孤儿行或误删 trust_device。
- **E2E 同步模式**：`E2ESyncDynamicProfile` 固定 `PUSH_PULL`。违反改为单方向：对端缺数据、不一致。
- **多用户读取**：读画像前 `IsMultiUserValid` 校验前台用户。违反：非前台用户读返回 `DP_GET_LOCAL_PROFILE_IS_NOT_FOREGROUND_ID`(98566279)。
- **删除本地约束**：`DeleteServiceProfile`/`DeleteCharacteristicProfile` 须 `IsLocalUdid` 校验。违反：删非本地设备返回 `DP_INVALID_PARAM`(98566245)。
- **下线不清理**：设备下线路径不级联清理数据，残留数据继续保留。违反：误以为下线即清空会导致排查方向错误。
