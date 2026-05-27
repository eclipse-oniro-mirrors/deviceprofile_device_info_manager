# DeviceProfile (device_info_manager) 领域知识库

> OpenHarmony 分布式设备画像管理模块 | SAID 6001 | subsystem: deviceprofile
> 最后更新: 2025-05-21 | 版本: v3.2

## 模块定位

DeviceProfile 是 OpenHarmony 分布式设备画像（Profile）的**集中式存储与同步管理层**，作为分布式系统中设备硬件能力、系统软件特征和信任关系信息的唯一权威数据源。其核心职责是：采集、存储、查询、同步和变更通知设备 Profile 数据。

**DeviceProfile 是：**
- 一个**持久化 Profile 仓库** — 管理 6 类 Profile 数据（设备画像、服务画像、特征画像、信任设备、访问控制、服务信息），跨越 3 种存储后端（KV 存储、RDB/SQLite、Asset 加密存储）
- 一个**数据同步引擎** — 在设备上线时自动推送/拉取 Profile 数据，支持 OH 设备和非 OH 设备的差异化同步
- 一个**变更通知中心** — 向已注册的订阅者分发 Profile 变更事件（增/删/改/激活/失活）

**DeviceProfile 不是：**
- 不是通信/传输层 — 不处理设备发现或 P2P 通信，委托给 SoftBus 和 DeviceManager
- 不是认证授权服务 — 存储信任关系但不执行认证协议，认证由 device_auth 处理
- 不是编排引擎 — 提供数据供上层消费，不做编排决策

**核心领域抽象：** Profile 数据管理 — 围绕设备画像全生命周期（采集、存储、同步、通知）的数据管理问题。

## 核心能力矩阵

| 能力域 | 具体功能 |
|--------|---------|
| **设备画像管理** | PutDeviceProfile / GetDeviceProfile / GetDeviceProfiles / DeleteDeviceProfileBatch |
| **服务画像管理** | PutServiceProfile / PutServiceProfileBatch / GetServiceProfile / DeleteServiceProfile |
| **特征画像管理** | PutCharacteristicProfile / PutCharacteristicProfileBatch / GetCharacteristicProfile / DeleteCharacteristicProfile |
| **信任关系管理** | PutAccessControlProfile / UpdateAccessControlProfile / DeleteAccessControlProfile / GetTrustDeviceProfile / GetAllTrustDeviceProfile |
| **访问控制管理** | GetAccessControlProfile / GetAllAccessControlProfile / GetAllAclIncludeLnnAcl |
| **画像同步** | SyncDeviceProfile / SyncStaticProfile / SendSubscribeInfos |
| **变更订阅** | SubscribeDeviceProfile / UnSubscribeDeviceProfile / SubscribeDeviceProfileInited / SubscribePinCodeInvalid |
| **服务信息管理** | PutServiceInfo / DeleteServiceInfo / GetAllServiceInfoList / GetServiceInfosByUserInfo |
| **本地服务管理** | PutLocalServiceInfo / UpdateLocalServiceInfo / GetLocalServiceInfoByBundleAndPinType / DeleteLocalServiceInfo |
| **会话密钥管理** | PutSessionKey / GetSessionKey / UpdateSessionKey / DeleteSessionKey |
| **业务事件管理** | PutBusinessEvent / GetBusinessEvent / RegisterBusinessCallback / UnRegisterBusinessCallback |
| **设备信息管理** | PutDeviceProfileBatch / PutProductInfoBatch / PutDeviceIconInfoBatch / GetDeviceIconInfos |
| **静态能力采集** | 启动时采集设备静态能力 + 动态加载静态能力收集器插件 |

## 场景快速参考

下表按使用场景分类，帮助快速定位到对应的文档。每个行对应一个"我想做什么"的入口。

| 我想做什么 | 推荐文档 | 关键入口 |
|-----------|---------|---------|
| 理解模块整体架构和分层设计 | `docs/01-architecture.md` | 第 2 节：内部四层架构图 + 模块职责矩阵 |
| 理解核心概念（Profile / ACL / Trust） | `docs/02-core-concepts.md` | 第 1 节：Profile 三层层级模型；第 3 节：概念对比表 |
| 查看关键数据结构定义 | `docs/03-data-structures.md` | 第 1 节：14 个核心 struct；第 2 节：枚举与错误码 |
| 了解服务的启动与关停流程 | `docs/04-workflows/01-service-lifecycle.md` | OnStart → PostInit → OnIdle → OnStop 完整时序 |
| 了解 Profile 的增删改查流程 | `docs/04-workflows/02-profile-crud.md` | Put / Get / Delete 三种 Profile 的完整调用链 |
| 了解信任设备和 ACL 的管理 | `docs/04-workflows/03-trust-acl-management.md` | PutACL → 级联删除 → 状态切换完整链路 |
| 了解跨设备 Profile 同步机制 | `docs/04-workflows/04-profile-sync.md` | OH 设备 KV 同步 vs 非 OH 设备 DP Sync Adapter |
| 了解订阅和事件通知机制 | `docs/04-workflows/05-subscription-notification.md` | Subscribe → Match → IPC 回调 → 去重逻辑 |
| 了解 ServiceInfo 的管理 | `docs/04-workflows/06-service-info-management.md` | 双层 KV 存储 + PublishState + PinCode 失效通知 |
| 了解设备上线/下线时的级联处理 | `docs/04-workflows/07-device-online-offline.md` | DMAdapter 事件消费 → E2E 同步触发 → 离线清理 |
| 了解本地数据采集流程 | `docs/04-workflows/08-content-collection.md` | ContentSensorManager + 6 个采集器的启动管线 |
| 了解会话密钥和业务事件 | `docs/04-workflows/09-sessionkey-business-event.md` | Asset 加密存储 + BusinessEvent KV 存储 + 回调 |
| 查找外部 API 的完整参考 | `docs/05-interfaces/01-external-api.md` | 50 个 API 的签名、权限、参数、错误码、示例 |
| 查找内部 API 约定 | `docs/05-interfaces/02-internal-api.md` | 内部 Manager 之间的调用约定 |
| 查找对外部模块的依赖 API | `docs/05-interfaces/03-dependency-api.md` | DP 对外部模块的 API 调用及约束 |
| 排查问题 / 查看日志 / 错误码 | `docs/06-debugging.md` | 日志域 0xD004400 / HiSysEvent / Radar / 故障排查流程 |
| 了解关键设计决策 | `docs/07-design-decisions.md` | ADR 格式的架构决策记录 |
| 查找常见问题 | `docs/08-faq.md` | 按场景分类的常见问题与解决方案 |
| 了解演进历史和未来计划 | `docs/09-roadmap.md` | 已完成的演进、进行中的功能和已知局限 |

## 全局术语表

| 缩写/术语 | 全称 | 含义 |
|----------|------|------|
| **DP** | DeviceProfile | 分布式设备画像模块的缩写，即本文档所描述的系统 |
| **ACL** | Access Control List | 访问控制列表，描述设备间的访问权控制关系——谁（Accesser）可以访问谁（Accessee），以何种方式（bindType/bindLevel） |
| **Accesser** | — | ACL 中的访问发起方，即主动建立信任关系的一方 |
| **Accessee** | — | ACL 中的访问接受方，即信任关系指向的目标方 |
| **LNN** | Local Network Negotiation | 本地网络协商——通过 SoftBus 自动发现并建立的局域网 ACL，区别于用户手动绑定的 ACL |
| **E2E** | End to End | 端到端同步模式。设备上线后自动执行 PUSH_PULL，确保两端 Profile 数据一致 |
| **SA** | System Ability | 系统能力，OpenHarmony 的服务单元。DP 注册为 SAID 6001，进程名 deviceprofile |
| **KV Store** | Key-Value Store | 分布式 KV 数据库（distributeddata），DP 用于跨设备 Profile 数据的自动同步 |
| **RDB** | Relational Database | 基于 SQLite 的关系型数据库（native_rdb），DP 用于需要关系完整性的数据（ACL、信任设备） |
| **Asset** | — | 硬件级加密存储 SDK（asset_sdk），DP 用于会话密钥等机密数据的安全存储 |
| **UDID** | Unique Device Identifier | 设备唯一标识符，DP 中所有 Profile 数据都以 UDID 作为设备维度的主键 |
| **UUID** | Universally Unique Identifier | 通用唯一标识符，作为 UDID 的备选设备标识类型 |
| **DM** | Device Manager | 设备管理模块（DeviceManager），负责设备发现和连接状态管理。DP 通过 DMAdapter 消费其事件 |
| **DMS** | Distributed Manager Service | 分布式管理服务框架，提供分布式基础能力 |
| **CS** | Content Sensor | 内容传感器，DP 的本地信息采集子系统，包含 6 个采集器 |
| **SysCap** | System Capability | 系统能力编解码，描述设备的软件能力集（如支持的 API、协议） |
| **OH** | OpenHarmony | OpenHarmony 操作系统。DP 区分 OH 设备（走 KV 分布式同步）和非 OH 设备（走 DP Sync Adapter） |
| **HiSysEvent** | — | 系统事件日志框架，DP 通过它上报同步成功/失败事件和 Radar 故障日志 |
| **IPC** | Inter-Process Communication | 进程间通信。DP 客户端与服务端之间通过 IRemoteBroker 的 proxy/stub 模式通信 |
| **Parcel** | — | IPC 序列化数据容器，DP 中所有 DpParcel 子类都实现了 Marshalling/Unmarshalling |

## 文档索引

### 基础文档
| 文档 | 概要 |
|------|------|
| `docs/01-architecture.md` | 系统栈中的模块定位、三层内部架构、核心模块职责矩阵、外部依赖总览 |
| `docs/02-core-concepts.md` | Profile / ACL / Trust 等核心领域概念、概念对比表 |
| `docs/03-data-structures.md` | 关键数据结构、枚举、字段语义和生命周期 |

### 业务工作流（核心）
| 文档 | 概要 |
|------|------|
| `docs/04-workflows/01-service-lifecycle.md` | SA 启动（OnStart）、后初始化（PostInit）、关停（OnStop）、空闲管理（OnIdle） |
| `docs/04-workflows/02-profile-crud.md` | Device / Service / Characteristic Profile 的增删查，含多用户键变体 |
| `docs/04-workflows/03-trust-acl-management.md` | 信任设备和访问控制 Profile 的生命周期，级联删除逻辑 |
| `docs/04-workflows/04-profile-sync.md` | 跨设备同步：OH 设备（KV Sync）、非 OH 设备（DP Sync Adapter）、静态同步 |
| `docs/04-workflows/05-subscription-notification.md` | Profile 变更订阅、初始化完成通知、PinCode 失效通知、业务事件通知 |
| `docs/04-workflows/06-service-info-management.md` | ServiceInfo CRUD（双 KV 存储）、LocalServiceInfo CRUD（RDB）、PinCode 失效触发 |
| `docs/04-workflows/07-device-online-offline.md` | DMAdapter 集成、设备上线数据修复、E2E 同步触发、设备离线清理 |
| `docs/04-workflows/08-content-collection.md` | ContentSensor 管理器 + 6 个采集器 + 静态能力采集管道 |
| `docs/04-workflows/09-sessionkey-business-event.md` | Asset 加密会话密钥管理、BusinessEvent 存储和回调通知 |

### 接口参考
| 文档 | 概要 |
|------|------|
| `docs/05-interfaces/01-external-api.md` | 50 个外部 API 的完整参考（签名、权限、参数、错误码、示例） |
| `docs/05-interfaces/02-internal-api.md` | 内部 Manager 间的调用约定 |
| `docs/05-interfaces/03-dependency-api.md` | DP 对外部模块的 API 调用和约束 |

### 运维文档
| 文档 | 概要 |
|------|------|
| `docs/06-debugging.md` | 日志标签（DHDP / 0xD004400）、HiSysEvent / Radar 定义、故障排查流程、依赖模块检查 |
| `docs/07-design-decisions.md` | ADR 格式的架构决策记录 |
| `docs/08-faq.md` | 按场景分类的常见问题 |
| `docs/09-roadmap.md` | 已完成的演进、进行中的功能和已知局限 |

## 贡献规则

修改本模块代码时，必须同步更新对应的知识库文档。以下规则确保文档与代码保持一致。

| 代码变更类型 | 需更新的文档 | 更新要点 |
|-------------|------------|---------|
| 新增/修改 `IDistributedDeviceProfile` 接口 | `docs/05-interfaces/01-external-api.md` + 对应工作流文档 | 更新 API 签名表格、IPC 接口码、错误码列表、调用流程说明 |
| 新增 Manager 模块 | `docs/01-architecture.md` 职责矩阵 + 对应工作流文档 | 在架构图中体现新模块、补充职责矩阵行、编写对应工作流文档 |
| 修改存储 schema（新增表/字段/索引） | `docs/03-data-structures.md` + `docs/01-architecture.md` | 更新对应 struct 定义、字段含义表、存储架构中的数据库描述 |
| 新增错误码 | `docs/06-debugging.md` + `docs/05-interfaces/01-external-api.md` | 补充到错误码分类表格中，确保命名和数值与实际定义一致 |
| 修改同步协议 | `docs/04-workflows/04-profile-sync.md` | 更新同步流程图、SyncMode 使用说明、OH/非 OH 设备差异描述 |
| 新增权限配置（修改 `permission.json`） | `docs/05-interfaces/01-external-api.md` + `docs/06-debugging.md` | 更新 API 与 caller process 的映射表、权限拒绝的排查指南 |
| 修改 feature flag（`deviceprofile.gni` 中的编译开关） | `docs/01-architecture.md` + `docs/09-roadmap.md` | 更新 feature flags 表格、roadmap 中对应功能的状态说明 |
| 新增采集器（ContentSensor collector） | `docs/04-workflows/08-content-collection.md` + `docs/01-architecture.md` | 补充采集器清单、职责矩阵 ContentSensorManager 行、采集管线说明 |

**注意事项：**
- 文档更新应与代码变更在同一 commit 中提交，或使用关联 commit message 引用
- 表格式文档（如错误码表、接口码表）应严格与源码中的枚举/常量定义保持一致，不要手工推算数值
- 工作流文档中的时序描述应反映实际调用链，避免"理想化"描述与实际代码行为的偏差
