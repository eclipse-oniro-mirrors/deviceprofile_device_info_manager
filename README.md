# 介绍<a name="ZH-CN_TOPIC_0000001128264105"></a>

-   [简介](#section11660541593)
-   [目录](#section1464106163817)
-   [约束](#section1718733212019)
-   [使用](#section10729231131110)
-   [涉及仓](#section176111311166)

## 简介<a name="section11660541593"></a>

DeviceProfile是设备硬件能力和系统软件特征的管理器，典型的Profile有设备类型、设备名称、设备OS类型、OS版本号等。DeviceProfile提供快速访问本地和远端设备Profile的能力，是发起分布式业务的基础。主要功能如下：

-   远程启动FA：跨设备拉起远端设备上指定FA。
-   远程迁移FA：将FA跨设备迁移到远端。
-   远程绑定AA：跨设备绑定远端设备上指定AA。  

DeviceProfile模块组成如下图所示：

## 系统架构<a name="section13587185873516"></a>

![](figures/dms-architecture_zh.png)

**图 1**  DeviceProfile组件架构图<a name="fig4460722185514"></a> 

## 目录<a name="section1464106163817"></a>

DeviceProfile主要代码目录结构如下：

```
├── BUILD.gn
├── include
│  ├── dmslite.h                             # 分布式调度对外接口
│  ├── dmslite_check_remote_permission.h     # 分布式调度权限管理模块
│  ├── dmslite_famgr.h                       # 分布式调度FA管理模块
│  ├── dmslite_inner_common.h                # 分布式调度内部通用文件
│  ├── dmslite.h                             # 分布式调度服务实现
│  ├── dmslite_log.h                         # 日志模块
│  ├── dmslite_parser.h                      # 分布式消息解析模块
│  ├── dmslite_tlv_common.h                  # TLV格式数据解析模块
│  └── dmslite_session.h                     # 跨设备通信收发模块
├── readme.md
├── LICENSE
├── source
    ├── distributed_schedule_service.c
    ├── dmslite.c
    ├── dmslite_check_remote_permission.c
    ├── dmslite_famgr.c
    ├── dmslite_msg_parser.c
    ├── dmslite_tlv_common.c
    └── dmslite_session.c
```

## 约束<a name="section1718733212019"></a>

-   组网设备需在同一局域网中。
-   组网之前，需先完成设备绑定，绑定流程参见安全子系统中说明。

## 使用<a name="section10729231131110"></a>

-   **分布式任务调度模块编译**

分布式任务调度模块，其代码所在目录如下：

```
foundation/distributedschedule/dmsfwk_lite
```

在针对不同平台进行编译时，需要提前指定目标平台：

```
hb build
```

## 涉及仓<a name="section176111311166"></a>

**[DeviceProfile子系统](zh-cn_topic_0000001115719369.md)**

[device\_profile\_core](https://gitee.com/openharmony-sig/device_profile_core)