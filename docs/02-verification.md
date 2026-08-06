# deviceprofile_device_info_manager 验证与调试规则

> 背景知识见 `knowledge/`；工作流时序见 `01-workflows.md`；构建与测试命令见 `03-build-test.md`。

## 1. 环境前置条件

- **设备组网：** 两板（或以上）须在同一局域网中；组网前须先完成设备绑定（绑定流程见安全子系统说明）。
- **依赖 SA 就绪：** DP 在 `PostInit` 前须等待 5 个依赖 SA 上线：`softbus_server`、`distributed_kv_data`(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID)、`device_manager`(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID=4802)、`os_account`(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN)、`memmgr`(MEMORY_MANAGER_SA_ID)。
- **关键就绪指标：** `PostInit finish` 日志出现→所有依赖就绪；`isInited_ = true`→缓存已 flush、可读；`depSaIds_` map 为空→所有依赖 SA 已上线。
- **KV 健康度：** KV store 初始化耗时若超过 6s（30 次 × 200ms 重试）说明 KV 服务异常。
- **账户与权限：** 多用户场景须有有效前台用户；受保护接口须以白名单进程（`device_manager`/`softbus_server`/`iShare`）身份调用。
- **版本对齐：** 分布式验证两板必须同步推包、同步重启，并等待 `BOOT_COMPLETED` 后再操作。

## 2. 验证命令

```bash
# DP 日志级别与限流
hdc shell hilog -b D -D 0xD004400
hdc shell hilog -Q off           # 临时关闭限流看完整日志
hdc shell hilog -T DHDP          # 实时过滤 DP 标签
hdc shell hilog -T DHDP > dp_debug.log   # 导出日志

# HiSysEvent 查询（域 DEVICE_PROFILE）
hdc shell hisysevent -d DEVICE_PROFILE
hdc shell hisysevent -d DEVICE_PROFILE -n DP_SYNC_FAILED
hdc shell hisysevent -l CRITICAL -d DEVICE_PROFILE

# SA dump（SAID 6001）
hdc shell hidumper -s 6001
hdc shell hidumper -s 6001 -h

# 进程与 SA 注册检查
hdc shell ps -ef | grep deviceprofile
hdc shell hidumper -l | grep 6001

# 关键行为日志过滤
hdc shell hilog -T DHDP -e "RegisterDataChangeListener\|UnRegisterDataChangeListener"
hdc shell hilog -T DHDP -e "OnRemoteDied\|ReInit"
hdc shell hilog -T DHDP -e "SyncDeviceProfile\|DP_SYNC"
hdc shell hilog -T DHDP -e "PostInit finish\|isInited_"
```

## 3. 日志标签

| 服务 | 日志标签 | 域 ID | 头文件 |
|------|----------|-------|--------|
| DeviceProfile | `DHDP` | `0xD004400` | `common/include/utils/distributed_device_profile_log.h` |

日志宏：`LOG_DOMAIN 0xD004400`、`LOG_TAG "DHDP"`；`HILOGF`/`HILOGE`/`HILOGW`/`HILOGI`/`HILOGD`。

## 4. HiSysEvent 定义

来源 `hisysevent.yaml`（域 `DEVICE_PROFILE`）。

| 事件名 | 类型 | 级别 | 标签 | 参数 |
|--------|------|------|------|------|
| `DP_SYNC_EVENT` | BEHAVIOR | MINOR | `deviceProfileSyn` | 无业务参数 |
| `DP_SYNC_FAILED` | FAULT | CRITICAL | — | `FAULT_CODE: INT32`（对应 DP 错误码） |

## 5. Radar 上报

来源 `radar/src/dp_radar_helper.cpp`、`radar/include/dp_radar_helper.h`（类 `DpRadarHelper` 单例，`SUBSYS_DISTRIBUTEDHARDWARE_DP=205`）。部分上报点：

| 方法 | 业务场景 | 阶段 |
|------|----------|------|
| `ReportCheckDpSa` / `ReportLoadDpSa` / `ReportLoadDpSaCb` | `DP_GET_SA` | 检查/加载 SA |
| `ReportSaCheckAuth` | `DP_GET_SA` | 调用者权限校验 |
| `ReportPutAclProfile` / `ReportUpdateAclProfile` / `ReportDeleteAclProfile` | ACL 操作 | `DP_PROFILE_OPERATE` |
| `ReportGetTrustProfile` / `ReportGetAllTrustProfile` | 查询信任设备 | `DP_PROFILE_OPERATE` |
| `ReportGetAclProfile` / `ReportGetAllAclProfile` | 查询 ACL | `DP_PROFILE_OPERATE` |
| `ReportPutServiceProfile` / `ReportPutServiceProfileBatch` | 写 ServiceProfile | `DP_PROFILE_OPERATE` |
| `ReportPutCharProfile` / `ReportPutCharProfileBatch` | 写 CharProfile | `DP_PROFILE_OPERATE` |
| `ReportSyncDeviceProfile` | 同步 | — |
| `ReportNotifyProfileChange` | 变更通知 | — |

## 6. 故障排查流程

| 现象 | 排查方向 | 关键日志/码 |
|------|----------|-------------|
| 调用即被拒 | 权限白名单 | `DP_PERMISSION_DENIED`(98566155)；查 `permission.json` 与 caller 进程名 |
| 调用返回服务未就绪 | 依赖 SA 未全上线 | `DP_LOAD_SERVICE_ERR`(98566160)；查 `depSaIds_`、`PostInit finish` |
| 调用返回服务空闲 | SA 进入空闲 | `DP_SERVICE_ON_IDLE`(98566330)；客户端应重试 |
| 调用返回服务停止 | SA 已停 | `DP_SERVICE_STOPPED`(98566331)；查 `OnStop` 触发原因 |
| KV 读写失败 | KV 服务/初始化 | `DP_PUT_KV_DB_FAIL`(98566197)/`DP_GET_KV_DB_FAIL`(98566199)/`DP_KV_DB_INIT_FAIL`(98566190) |
| RDB 操作失败 | schema/迁移 | `DP_RDBADAPTER_*`(98566209+)；查 `RDB_VERSION` 与 `OpenCallback` 迁移 |
| 同步失败 | OH：KV 同步；非 OH：适配器 | `DP_KV_SYNC_FAIL`(98566204)/`DP_LOAD_SYNC_ADAPTER_FAILED`(98566248) |
| ACL 写入失败 | 重复/不可变字段 | `DP_DATA_EXISTS`(98566253)/`DP_UPDATE_ACL_NOT_ALLOW`(98566249) |
| 通知未投递 | 订阅键后缀不一致/超限 | `DP_EXCEED_MAX_SIZE_FAIL`；查 `DBKeyToSubcribeKey` 与 OH 后缀 |

## 7. 环境特性

- **两板同步：** 分布式验证两板必须同步推包、同步重启、等待 `BOOT_COMPLETED`，否则会因版本/SA 状态不一致导致同步异常。
- **下线不清理：** 设备下线路径不级联清理数据，已断开设备的残留画像继续保留在存储中；排查"幽灵数据"时须结合上线/绑定历史。
- **KV 死亡恢复：** KV 服务死亡由 `KvStoreDeathRecipient` 恢复 4 个独立 KV store；查 `OnRemoteDied`/`ReInit` 日志确认恢复。
- **非 OH 设备同步：** 依赖 `libdeviceprofileadapter.z.so` 插件在 `LIB_LOAD_PATH`（如 `/system/lib64/`）；缺失则非 OH 路径不可用。
- **手表形态：** `device_info_manager_adaptation_watch=true` 时启用 `etc/init/watch/deviceprofile.cfg`（额外 `importance:-20`）与 `WATCH_SUPPORT` 编译宏。
