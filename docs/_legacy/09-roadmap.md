# 09 - 演进路线图

> DeviceProfile 模块版本历史、已知局限与未来方向 | 最后更新: 2025-05-21

---

## 1. 版本历史

### 当前版本：v3.1

代码库目前处于 `v3.1` 版本，经历了多轮架构优化。

### v1.x -- 原始 Profile 管理（约 2021-2022）
- **基础建设:** SA 6001 建立，以 basic KV store (`DistributedKv`) 作为唯一的持久化层
- **核心 API:** `PutDeviceProfile`、`GetDeviceProfile`、`PutServiceProfile`、`PutCharacteristicProfile` 及其 CRUD 变体
- **同步:** 通过 DistributedKv 实现基本的 PUSH_PULL 同步，手动触发
- **订阅:** 简单的 Profile 变更监听器注册
- **权限模型:** 全有或全无的权限检查，无按方法白名单
- **参考:** 旧代码路径保留在 `old/` 目录中（为迁移兼容性保留）

### v2.x -- RDB 支持、Trust/ACL、多用户（约 2022-2023）
- **新增 RDB 后端:** `native_rdb` (SQLite) 引入，与 KV store 并存以支持关系查询
- **信任 Profile 管理:** 新增 `TrustProfileManager` -- `PutAccessControlProfile`、`UpdateAccessControlProfile`、`DeleteAccessControlProfile`、`GetTrustDeviceProfile`、`GetAllTrustDeviceProfile`
- **ACL 模型:** Accesser/Accessee 配对模型用于方向性信任关系
- **多用户支持:** 新增 `MultiUserManager`，key 标注 `#userId` 后缀，前台用户提升，删除用户级联
- **权限粒度化:** `permission.json` 支持按方法进程白名单（`"all"` 级别和命名进程级别）
- **内容传感器框架:** `ContentSensorManager` + 采集器插件架构（system info、syscap、DMS、pasteboard、collaboration、switch status）
- **Device Manager 集成:** `DMAdapter` 用于设备上线/离线生命周期事件
- **服务生命周期:** 引入按需启动模型（仅在设备上线或启动完成时启动）

### v3.0 -- ServiceInfo 模型、静态能力、Switch 管理（约 2023-2024）
- **ServiceInfo 模型:** 新增 `ServiceInfoManager`，双层 KV 存储（本地 + 同步 store），`ServiceInfo` 数据类型包含用户信息
- **本地服务信息:** `LocalServiceInfoManager` 管理 bundle 范围的本地服务元数据，支持 pin 交换类型
- **静态能力采集:** `StaticCapabilityCollector` + `StaticCapabilityLoader` -- 启动时采集设备静态能力，支持动态 `.so` 插件加载
- **Switch Profile 管理:** `SwitchProfileManager` 从 DeviceProfileManager 中分离 -- 处理 switch 状态 CharacteristicProfile，使用专门的 JSON 格式 switch 配置
- **Feature Flag:** `device_info_manager_supported_switch` 在编译时控制 switch profile 功能可用性
- **Profile 数据管理:** `ProfileDataManager` 将 Device Profile、Product Info 和 Device Icon Info 统一到 RDB 中，通过 DAO 层管理
- **Settings 数据管理:** `SettingsDataManager` 用于 Settings 数据集成
- **公共事件发布:** `DpAccountCommonEventManager` 用于账户生命周期事件（用户切换、用户删除）
- **Radar/DFX:** 新增 `DpRadarHelper`，包含 20+ 个 HiSysEvent 上报点，覆盖 SA 生命周期和 profile 操作

### v3.1 -- 业务事件、会话密钥、本地服务信息、DP 同步适配器（约 2024-2025）
- **业务事件管理器:** `BusinessEventManager` 实现 `PutBusinessEvent`/`GetBusinessEvent`，支持通过 `IBusinessCallback` 的回调通知
- **会话密钥管理:** `SessionKeyManager` 使用 Asset（硬件加密存储）进行会话密钥 CRUD
- **本地服务信息 CRUD:** 通过 `LocalServiceInfoManager` 实现完整的本地服务信息生命周期
- **DP 同步适配器:** 使用动态库 (`dlopen`) 方式支持非 OH 设备同步 (`DP_SYNC_ADAPTER`)
- **PinCode 失效通知:** `SubscribePinCodeInvalid`/`UnSubscribePinCodeInvalid` + `NotifyPinCodeInvalid` 回调链
- **Device Profile 初始化订阅:** `SubscribeDeviceProfileInited` 供等待 DP 完全初始化的服务使用
- **Service Info 订阅:** `SubscribeAllServiceInfo` 用于 ServiceInfo 变更通知
- **Device Icon Info:** `PutDeviceIconInfoBatch`/`GetDeviceIconInfos`/`DeleteDeviceIconInfo`
- **Product Info 批量操作:** `PutProductInfoBatch`/`DeleteProductInfoBatch`
- **KV 死亡恢复改进:** 四个独立的 KV store，各自具有独立的 `KvDeathRecipient` 恢复路径
- **Schema 迁移支持:** 新增 `DP_PRE_MIGRATION_DB_*` 错误码，用于 RDB schema 迁移兼容性

---

## 2. 功能标志（Feature Flags）作为演进控制

DP 使用编译时 feature flags 控制功能的渐进式开放，避免全量构建中出现不可用功能：

| 标志 | 默认值 | 禁用时的效果 |
|------|---------|---------------------|
| `device_info_manager_capability` | `true` | SDK 和 service 使用最小 stub 构建 (`*_fail_to_support.cpp`)；大多数 Profile CRUD 返回 `DP_NOT_SUPPORT` |
| `device_info_manager_supported_switch` | `true` | Switch profile 管理被编译排除；`PutCharacteristicProfile` 返回 `DP_DEVICE_UNSUPPORTED_SWITCH` |
| `dp_os_account_part_exists` | 自动检测 | 当 `account_os_account` 部件不在构建中时，通过 `-DDP_OS_ACCOUNT_PART_EXISTS` 禁用多用户功能 |
| `device_info_manager_common` | 自动检测 | 当为 false 时（分布式硬件适配器存在），设置 `-DDEVICE_PROFILE_SWITCH_DISABLE` 和 `-DDEVICE_PROFILE_STATIC_DISABLE` |

此标志架构允许：
- **渐进式推出:** 新功能可在早期构建中默认为 `false`，稳定后提升为 `true`。
- **平台变体:** IoT/轻量设备可禁用 switch 和 static capability，同时保留核心 Profile CRUD。
- **构建安全:** 依赖不存在系统部件的功能被编译排除，而非在运行时失败。

---

## 3. 已知局限

### KV Store 冷启动数据窗口
**问题:** 在服务启动期间，KV store 在 `PostInit()` 完成（全部 5 个依赖 SA 上线）之前不可用。此窗口期间的写入进入临时缓存。如果进程在缓存刷新之前崩溃（约 5 秒宽限期 + 最多 20 次重试，每次 200ms），缓存数据会丢失。

**应对措施:** 带重复检测和重试的临时缓存 (ADR-004)。`ResetFirst()` 回退是承认数据丢失的最后手段。客户端不应依赖服务启动最初 5-10 秒内提交的写入能在崩溃后存活。

**风险:** 低概率但高影响 -- 在启动崩溃期间丢失信任 profile 或服务信息需要重新配对或重新发布。

### LNN ACL 公开 API 过滤（非完全隔离）
**问题:** LNN ACL 与用户绑定 ACL 存储在同一 RDB 表中。过滤通过 `extraData` JSON 标志约定实现，非法模式强制。如果新的查询路径遗漏了过滤条件，会悄然将 LNN ACL 暴露给应用程序。

**当前缓解措施:** `GetAllAccessControlProfile()` 在 `TrustProfileManager` 中应用过滤条件。`GetAllAclIncludeLnnAcl()` 在 `permission.json` 中受到权限限制。然而，没有架构保证新的代码路径始终会正确过滤。

### 非 OH 设备同步需要 dp_sync_adapter 插件
**问题:** 向非 OpenHarmony 设备同步 profile 数据需要动态加载 `dp_sync_adapter.so`。此库不是核心构建的一部分，可能并非在所有设备上都可用。没有它，非 OH 设备同步会悄然失败，返回 `DP_LOAD_SYNC_ADAPTER_FAILED`。

**影响:** 跨生态系统同步（如 OH 手机到旧版 HarmonyOS 平板）受限于平台特定的适配器可用性。

### 1000 项订阅者上限
**问题:** `MAX_CALLBACK_LEN = 1000` 是对订阅、初始化通知、PinCode 失效通知和业务事件通知的注册回调数量的硬性限制。在拥有大量订阅者 SA 的大规模部署中可能达到此限制。

**影响:** 当达到上限时，新订阅者会收到 `DP_SUBSCRIBE_LIMIT_EXCEEDED` 或 `DP_INVALID_PARAM`，无法注册。如果订阅失败，服务必须实现回退轮询机制。

### 静态能力插件需要 .so 加载
**问题:** 静态能力采集器通过 `StaticCapabilityLoader` 以 `.so` 插件形式加载。如果插件 `.so` 缺失或不兼容，其能力类型仅会从采集的 profile 中缺失，除了错误日志外没有运行时警告。没有内省 API 来确定当前可用的能力。

### 无跨后端事务支持
**问题:** 跨越 KV store 和 RDB 的操作（如将 TrustDeviceProfile 添加到 KV 的同时在 RDB 中更新 ACL）不是事务原子性的。两次写入之间的崩溃会留下部分提交状态。

---

## 4. 迁移路径

### RDB Schema 迁移

代码库通过 `DP_PRE_MIGRATION_DB_*` 错误码和相关迁移逻辑支持跨版本数据库 schema 迁移：

| 阶段 | 错误码 | 含义 |
|-------|-----------|---------|
| 预检查 | `DP_PRE_MIGRATION_DB_AVAILABLE` (98566339) | 旧版本数据库可访问 |
| 预检查 | `DP_PRE_MIGRATION_DB_UNAVAILABLE` (98566340) | 旧版本数据库无法访问（可能损坏或路径错误） |
| 判定 | `DP_NOT_NEED_MIGRATION` (98566341) | 当前 schema 与预期版本匹配；无需迁移 |

**迁移流程:**
1. 服务启动时检测旧版本数据库表
2. 如果 `DP_PRE_MIGRATION_DB_AVAILABLE`，将旧数据读入内存
3. 创建新版本表（当前 schema）
4. 将旧数据转换为新 schema 格式
5. 将转换后的数据写入新表
6. 标记迁移完成

### v1 到 v2 迁移
- 旧的纯 KV 数据迁移到 RDB 表，用于 Trust/ACL/ServiceProfile
- 旧的扁平 key 格式转换为新的多段 key 格式
- `old/` 目录下的旧代码路径保留，用于读取旧版格式

### v2 到 v3 迁移
- ServiceInfo 数据从单一 KV store 迁移到双层（本地 + 同步）
- Switch profiles 从动态 Characteristic profiles 分离到 `SwitchProfileManager`
- Device Icon Info 和 Product Info 迁移到 DAO 管理的 RDB 表中

### 迁移安全性
- 迁移是幂等的：对已迁移的数据库再次执行迁移是空操作 (`DP_NOT_NEED_MIGRATION`)
- 原始表在迁移期间保留（不删除），以允许回滚
- 所有迁移操作都有日志记录，可审计

---

## 5. 未来方向

基于代码模式、feature flags 和代码库中观察到的架构演进：

### Asset 集成扩展
Asset 存储后端目前仅用于会话密钥。基础设施已就绪 (`AssetAdapter`、`DP_ASSET_*` 错误码)，可将 Asset 扩展用于：
- 信任设备凭据的加密存储
- ACL 相关密钥的安全存储
- 硬件级 profile 完整性验证

### 更丰富的服务发现模型
双层 ServiceInfo KV store (ADR-003) 为更复杂的服务发现框架提供了基础：
- 带 TTL 的服务能力广告
- DP 中服务网格风格的路由信息
- 超越简单在线/离线的动态服务可用性跟踪

### Schema 验证与迁移框架
当前 RDB 迁移逻辑是手动的。未来迭代可增加：
- 声明式 schema 版本系统 (`DP_SCHEMA_VERSION`)
- 无需自定义迁移代码的自动列添加
- 迁移演练和测试验证基础设施

### 非 OH 同步适配器标准化
基于 `dlopen` 的同步适配器 (ADR-005) 可演进为：
- 带版本协商的标准化同步适配器接口
- 多适配器支持（每种非 OH 设备类型一个）
- 优雅降级：在无法完成全量同步时执行部分同步

### 订阅优化
当前订阅模型使用扁平列表，O(n) 匹配。对于接近 1000 订阅者上限的部署：
- 索引订阅匹配（按 deviceId、serviceName）
- 订阅去重与合并
- 基于模式的订阅（通配符 characteristic keys）

### 可配置的限制
硬编码的限制（`MAX_CALLBACK_LEN = 1000`、`DELAY_TIME = 180000`、重试次数）可迁移到配置：
- 系统参数覆盖以支持部署特定调优
- 基于可用内存的动态限制调整
- 每个调用者的订阅配额

### 可观测性改进
当前的 DFX 能力（dumper、radar）可扩展： 
- Profile 数据统计（按类型的计数、每个后端的存储大小）
- 同步延迟和吞吐量指标
- 热 profile 检测（最频繁访问的 key）
