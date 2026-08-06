# deviceprofile_device_info_manager 构建、测试与验证规则

> 背景知识见 `knowledge/`；工作流时序见 `01-workflows.md`；验证与调试命令见 `02-verification.md`。

## 1. 构建入口

- **构建系统：** GN + Ninja（OpenHarmony 标准构建）。
- **命令运行目录：** OpenHarmony 源码根目录（不是本子仓目录）。本仓在源码树中路径为 `foundation/deviceprofile/device_info_manager`。
- **编译选项：** `deviceprofile.gni` 设 `build_flags = ["-Werror"]`，警告即错误。
- **根构建目标（GN label）：**

```text
# 服务侧
//foundation/deviceprofile/device_info_manager/services/core:distributed_device_profile_svr
//foundation/deviceprofile/device_info_manager/common:distributed_device_profile_common
//foundation/deviceprofile/device_info_manager/radar:device_profile_radar
//foundation/deviceprofile/device_info_manager/sa_profile:dps_sa_profile
//foundation/deviceprofile/device_info_manager/etc/init:etc
//foundation/deviceprofile/device_info_manager/etc/profile:deviceprofile_trust
//foundation/deviceprofile/device_info_manager/permission:permission_json

# 客户端 SDK
//foundation/deviceprofile/device_info_manager/interfaces/innerkits/core:distributed_device_profile_sdk
```

`bundle.json` 的 `group_type` 将上述分为 `fwk_group`（sdk + common）与 `service_group`（svr + 配置 + sa_profile + permission）。

## 2. 测试目标

测试输出路径 `device_info_manager/device_info_manager`（`deviceprofile.gni` 的 `fuzz_test_output_path`）。

```text
# 单元测试（bundle.json test 引用）
//foundation/deviceprofile/device_info_manager/services/core:unittest
//foundation/deviceprofile/device_info_manager/radar/test/unittest:dp_radar_helper_test_new
//foundation/deviceprofile/device_info_manager/common/test:common_test

# Fuzz 测试
//foundation/deviceprofile/device_info_manager/services/core/test/fuzztest:fuzztest
```

`services/core:unittest` 组含 53 个 `ohos_unittest` 目标，覆盖各 Manager/适配器/监听器/工具/Stub/Client/Proxy/DAO。`fuzztest` 组含 8 个 `ohos_fuzztest`：`AllInterfaceFuzzTest`、`HighRiskInterfaceFuzzTest`、`NewDeviceProfileFuzzTest`、`ProfileUtilsFuzzTest`、`BusinessEventManagerFuzzTest`、`ServiceInfoClientFuzzTest`、`ServiceInfoProxyFuzzTest`、`TrustProfileFuzzTest`。

## 3. 变更类型 → 验证要求 → 最低证据

| 变更类型 | 验证要求 | 最低证据 |
|----------|----------|----------|
| 新增/修改 `IDistributedDeviceProfile` 接口或接口码 | 全链路单测 + IPC 桩测 + 权限测 + 板级跨设备验证 | `services/core:unittest` 全绿；`distributed_device_profile_stub_new_test` 通过；两板同步成功日志 |
| 修改 Manager 业务逻辑 | 对应 Manager 单测 + 受影响流程板级验证 | Manager 单测全绿；`02-verification.md` 关键日志出现 |
| 修改存储 schema（KV storeId / RDB 表/字段/索引/版本） | 适配器单测 + 迁移验证 + 板级重启验证 | `kv_adapter_new_test`/`rdb_adapter_new_test` 通过；旧库升级后读列成功；重启后 `isInited_ = true` |
| 修改同步协议/适配器 | 同步单测 + 非 OH（若涉及）+ 板级 E2E 验证 | `kv_sync_completed_listener_test` 通过；`DP_SYNC_EVENT` 上报；E2E `PUSH_PULL` 日志 |
| 修改订阅/通知 | 订阅单测 + 板级变更通知验证 | `subscribe_profile_manager_test` 通过；通知 IPC 回调命中 |
| 修改 `permission.json` | 权限单测 + 板级鉴权验证 | `PermissionManagerTest` 通过；非白名单进程被拒日志 |
| 修改 feature flag（`deviceprofile.gni`） | 条件编译分支单测 + 板级编译验证 | 对应开关下 `services/core:unittest` 全绿；目标产物按预期产出/不产出 |
| 新增采集器 | 采集单测 + 板级启动验证 | `content_sensor_*_test` 通过；启动后采集画像写入日志 |

## 4. 最低检查项（按变更类型）

- **接口变更：** 接口码枚举、Stub 派发表、Proxy `SEND_REQUEST`、`permission.json`、回调 stub/proxy、测试与 mock 六端同步（见 `AGENTS.md` 接口码约束）。
- **Manager 变更：** `Init`/`PostInit`/`UnInit` 三处同步；锁保护范围；错误码返回与头文件一致。
- **存储变更：** `RDB_VERSION` 升级 + `OpenCallback` 迁移 SQL；KV 选项与目录权限一致；监听器注册。
- **同步变更：** `FilterAndGroupOnlineDevices` 分组、`AddSyncListener`/`RemoveSyncListeners`、`SyncCompleted` 回调三处同步；E2E 保持 `PUSH_PULL`。
- **订阅变更：** `ProfileChangeType`、`funcsMap_`、`DBKeyToSubcribeKey`、`Notify*`、回调 IPC 码、测试六端同步。

## 5. 板级验证

### 5.1 环境要求

| 项 | 要求 |
|----|------|
| 设备 | ≥2 台 OpenHarmony 设备（OH 设备间验证 KV 同步）；非 OH 验证需适配器插件 |
| 网络 | 同一局域网 |
| 绑定 | 组网前完成设备绑定 |
| 版本 | 两板同步推包、同步重启、等待 `BOOT_COMPLETED` |
| 账户 | 多用户场景须有效前台用户 |

### 5.2 验证命令

见 `02-verification.md` 第 2 节（hilog / hisysevent / hidumper -s 6001）。

### 5.3 关键日志关键字

| 关键字 | 含义 |
|--------|------|
| `PostInit finish` / `isInited_ = true` | 服务初始化完成，可读 |
| `SyncDeviceProfile` / `DP_SYNC` | 同步行为 |
| `DP_SYNC_EVENT` / `DP_SYNC_FAILED` | 同步成功/失败 HiSysEvent |
| `RegisterDataChangeListener` / `UnRegisterDataChangeListener` | KV 监听注册 |
| `OnRemoteDied` / `ReInit` | KV 死亡恢复 |
| `OnDeviceOnline` / `OnNodeOnline` | 设备上线 |
| `NotifyProfileChange` | 变更通知 |

### 5.4 PR 证据模板

```text
## 板级验证证据
- 设备：A(udid/版本) ↔ B(udid/版本)，同局域网，已绑定
- 推包：两板同步推包 commit <hash>，重启，等待 BOOT_COMPLETED
- 用例：<变更类型对应场景，如 PutDeviceProfile 后 GetDeviceProfile 一致>
- 日志：
  - hdc shell hilog -T DHDP 关键片段（含 PostInit finish / SyncDeviceProfile / DP_SYNC_EVENT）
  - hdc shell hidumper -s 6001 画像 dump 对比
  - hdc shell hisysevent -d DEVICE_PROFILE（无 DP_SYNC_FAILED）
- 结果：两板数据一致；无 DP_SYNC_FAILED / DP_PERMISSION_DENIED / DP_LOAD_SERVICE_ERR
```

## 6. Feature Flag 表

来源 `deviceprofile.gni` 与各 `BUILD.gn`。

| Flag | 默认值 | 作用 | 影响 |
|------|--------|------|------|
| `device_info_manager_supported_switch` | `true` | 是否支持开关数据 | `false` 或 `device_info_manager_common` 为真 → 定义 `DEVICE_PROFILE_SWITCH_DISABLE`，禁用 `SwitchProfileManager` 及其测试 |
| `device_info_manager_capability` | `true` | 整体能力开关 | `false` → svr/sdk/radar `install_enable=false`，SDK 用 `distributed_device_profile_client_fail_to_support.cpp` 桩 |
| `device_info_manager_adaptation_watch` | `false` | 适配手表形态 | `true` → 定义 `WATCH_SUPPORT`，启用 `etc/init/watch/deviceprofile.cfg` |
| `dp_os_account_part_exists` | 由 `global_parts_info.account_os_account` 决定 | 是否引入 os_account 部分 | 存在 → 定义 `DP_OS_ACCOUNT_PART_EXISTS` |
| `device_info_manager_common` | 存在 `distributedhardware_distributed_hardware_adapter` 部分则 `false`，否则 `true` | "common/精简"形态 | 为真 → 定义 `DEVICE_PROFILE_STATIC_DISABLE`，禁用静态能力 |

条件编译宏汇总：`DEVICE_PROFILE_SWITCH_DISABLE`、`DEVICE_PROFILE_STATIC_DISABLE`、`DP_OS_ACCOUNT_PART_EXISTS`、`WATCH_SUPPORT`。

## 7. 常见误用

| 误用 | 后果 | 修正 |
|------|------|------|
| 在本子仓目录运行构建命令 | 找不到 GN 根与依赖 | 在 OpenHarmony 源码根目录运行 |
| 关 `device_info_manager_capability` 但不重编 SDK | SDK 仍走真实实现，与桩不一致 | 同步重编 sdk/svr/radar |
| 升级 RDB schema 不升 `RDB_VERSION` | 旧库不迁移，读列失败返回 `DP_GET_RESULTSET_FAIL`(98566220) | 升 `RDB_VERSION` 并写 `OpenCallback` 迁移 SQL |
| 改 KV storeId 不改目录权限 | KV 打不开返回 `DP_KV_DB_INIT_FAIL`(98566190) | 同步 `deviceprofile.cfg` 的 mkdir |
| 用旧文档错误码值排查 | 误判（文档旧名与头文件值不一致） | 以 `distributed_device_profile_errors.h` 头文件为准 |
| 板级验证只推一板 | 版本/SA 状态不一致导致同步异常 | 两板同步推包、同步重启、等待 `BOOT_COMPLETED` |
| 只跑单测不做板级跨设备验证 | 同步/通知类缺陷漏网 | 同步/订阅/上线类变更必须板级验证 |

## 8. 完成定义（Definition of Done）

- [ ] `services/core:unittest`、`common:test`、`radar:test`、`fuzztest` 四组全绿。
- [ ] 对应变更类型的最低检查项全部完成（第 4 节）。
- [ ] 板级验证证据齐全（第 5.4 节模板），无 `DP_SYNC_FAILED`/`DP_PERMISSION_DENIED`/`DP_LOAD_SERVICE_ERR` 等异常码。
- [ ] 接口/错误码/枚举表与源码头文件一致（不手工推算数值）。
- [ ] 若改了接口码、schema、权限、feature flag，已同步本知识库对应文档。
