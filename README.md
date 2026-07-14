# lpe-checker

`lpe-checker` 是一个**只读**的 Linux 本地提权（Local Privilege Escalation, LPE）风险检测工具，支持在 Linux 主机上运行 CLI 本地扫描，也支持通过 Fyne GUI 使用 SSH 密码认证远程、批量扫描多台 Linux 主机。

工具只采集系统事实并在操作端匹配规则：**不执行漏洞利用，不触发 CVE，不加载或卸载内核模块，也不修改目标系统状态。**

## 1. 项目简介

- CLI：在被检测的 Linux 主机上执行本地只读扫描。
- GUI：可在 Windows/Linux 等操作端通过 SSH 扫描远程 Linux 主机。
- 批量：手动添加主机或从 CSV 导入，使用低并发工作池逐台扫描。
- 规则驱动：内置 YAML 规则，也可加载外部规则并按 ID 覆盖内置规则。
- 报告：中文文本、结构化 JSON、单文件中文 HTML。

## 2. 功能特性

### 扫描与报告

- 本地 CLI 扫描。
- SSH 密码认证远程扫描；目标 Linux 主机不需要安装 `lpe-checker`。
- GUI 批量扫描，默认最大并发数为 3；单台失败不终止整批。
- GUI 支持手动添加、删除和编辑主机，以及 CSV 导入。
- GUI 支持扫描前勾选规则；未勾选规则不会进入评估。
- GUI 总览/详情分屏，当前选中主机可单独导出 HTML 或 JSON。
- CLI 默认输出中文文本，也可输出 JSON、JSON 文件和单文件 HTML。

### 规则与检测类型

规则加载顺序为：内置规则 → 外部规则。同 ID 的外部规则覆盖内置规则。

当前支持的 `match.type`：

| 类型 | 含义 |
|---|---|
| `kernel_contains` | 内核版本字符串包含匹配 |
| `kernel_cve_module` | Linux 内核模块状态启发式 CVE 检测 |
| `kernel_version_range` | 上游内核版本区间启发式 CVE 检测（命中固定为 suspected/medium） |
| `os_id` | `/etc/os-release` 的 `ID` 精确匹配（忽略大小写） |
| `sudo_contains` | `sudo -n -l` 输出包含匹配 |
| `suid_path` | 固定候选路径中存在指定 SUID 文件 |
| `user_contains` | `id` 输出包含匹配 |
| `os_release_contains` | OS ID、名称、版本和 Pretty Name 的组合文本包含匹配 |

内置规则：

- `LPE-SUDO-NOPASSWD`
- `LPE-SUID-PKEXEC`
- `LPE-SUID-FIND`
- `LPE-SUID-BASH`
- `LPE-SUID-VIM`
- `CVE-2026-31431`（只读疑似暴露条件示例）
- `CVE-2026-46242`（Bad Epoll 上游版本区间启发式检测）
- `CVE-2026-31694`（FUSE readdir OOB 上游版本区间启发式检测）
- `LPE-XFRM-ESP-FAMILY`（XFRM/ESP 模块家族启发式检测）
- `CVE-2026-46331`（act_pedit 模块启发式检测）

### 只读安全边界

- 本地采集通过 `CommandRunner` 统一执行只读命令。
- SSHRunner 使用固定命令形态校验和逐参数 shell 单引号转义。
- SSH 只允许采集所需的 `uname`、`id`、`sudo -n -l`、`lsmod`、`cat /etc/os-release`、`hostname` 和两种固定 `find` 形态；不提供任意 shell 命令入口。
- 单条采集失败不会让整个扫描流程立即退出；依赖失败采集项的 check 会记录为 `failed/unknown`。

> [!WARNING]
> 当前 SSH 第一版使用 `ssh.InsecureIgnoreHostKey()`，尚未进行 `known_hosts` 主机密钥校验。请只在可信网络和已授权环境中使用，并独立核对目标主机身份。

## 3. 安装与构建

### 环境要求

- Go `1.22`（见 `go.mod`）。
- CLI 不依赖 CGO。
- GUI 使用 Fyne `v2.5.5`，需要 `CGO_ENABLED=1`、C 编译器和平台图形开发库。

先获取代码并进入项目目录：

```bash
git clone <your-repository-url>
cd go-fyne-linux-1-lpe-checker
go mod download
```

### 构建 CLI

Linux/macOS：

```bash
CGO_ENABLED=0 go build -o lpe-checker-cli ./cmd/lpe-checker-cli
```

Windows PowerShell：

```powershell
$env:CGO_ENABLED = "0"
go build -o lpe-checker-cli.exe ./cmd/lpe-checker-cli
```

随附脚本：

```text
build-cli.sh
build-cli.bat
build-cli.ps1
```

如果要在 Windows 上交叉编译 Linux amd64 CLI：

```powershell
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -o lpe-checker-cli-linux-amd64 ./cmd/lpe-checker-cli
```

### 构建 Windows GUI

需要：

1. Go 1.22。
2. MSYS2/MinGW-w64 GCC，并确保 `gcc.exe` 位于 `PATH`。
3. `CGO_ENABLED=1`。

PowerShell：

```powershell
$env:CGO_ENABLED = "1"
go build -ldflags="-H windowsgui" -o lpe-checker-gui.exe ./cmd/lpe-checker-gui
```

CMD：

```bat
set CGO_ENABLED=1
go build -ldflags="-H windowsgui" -o lpe-checker-gui.exe ./cmd/lpe-checker-gui
```

`-H windowsgui` 用于避免启动 GUI 时弹出额外控制台窗口。随附脚本：

```text
build-gui.bat
build-gui.ps1
```

### 构建 Linux GUI

Fyne 官方文档列出的 Debian/Ubuntu 开发依赖为：

```bash
sudo apt-get install golang gcc libgl1-mesa-dev xorg-dev libxkbcommon-dev
```

其他发行版请参考 [Fyne Quick Start](https://docs.fyne.io/started/quick/)。安装依赖后：

```bash
CGO_ENABLED=1 go build -o lpe-checker-gui ./cmd/lpe-checker-gui
```

也可运行 `build-gui.sh`。

### 关于 `CGO_ENABLED=0`

禁用 CGO 时，`cmd/lpe-checker-gui/main_nocgo.go` 只会构建一个提示桩；运行它不会显示图形界面。CLI 可在 `CGO_ENABLED=0` 下正常构建和运行。

## 4. 使用方法

### CLI：Linux 本地扫描

CLI 子命令是 `scan`，不是 `--scan`。应在被检测的 Linux 主机上运行。

默认中文文本输出：

```bash
./lpe-checker-cli scan
```

输出 JSON 到标准输出：

```bash
./lpe-checker-cli scan --json
```

写入 JSON 文件：

```bash
./lpe-checker-cli scan --output result.json
```

写入单文件 HTML，并继续输出默认文本：

```bash
./lpe-checker-cli scan --html report.html
```

同时写入 HTML 和 JSON 文件：

```bash
./lpe-checker-cli scan --html report.html --output result.json
```

使用指定外部规则目录：

```bash
./lpe-checker-cli scan --rules /path/to/rules
```

组合示例：

```bash
./lpe-checker-cli scan --json --output result.json --html report.html --rules /path/to/rules
```

参数行为：

| 参数 | 行为 |
|---|---|
| `--json` | 使用 JSON 模式；未指定 `--output` 时打印到 stdout |
| `--output <file>` | 将 JSON 写入文件；不要求同时指定 `--json` |
| `--html <file>` | 将同一次扫描的 Report 写为单文件 HTML |
| `--rules <dir>` | 加载指定外部规则目录；目录必须存在且可读 |

未指定 `--rules` 时，如果当前目录存在 `./rules`，会自动加载；不存在不报错。

### GUI：SSH 远程/批量扫描

GUI 在操作端运行，通过 SSH 密码认证连接 Linux 主机，执行固定只读采集命令；规则匹配和报告生成在操作端完成，目标主机无需安装本工具。

基本流程：

1. 输入 Host/IP、端口、用户名和密码。
2. 根据需要添加或删除主机。
3. 勾选要评估的规则；默认全选。
4. 点击“批量扫描”。
5. 在左侧查看各主机状态和风险摘要，点击主机在右侧查看详情。
6. 对当前选中的成功报告导出 HTML 或 JSON。

当前批量工作池最大并发数固定为 3，GUI 暂不提供并发数配置。

#### CSV 导入

列顺序：

```csv
主机,端口,用户名,密码
192.0.2.1,22,root,example-password
```

- 可包含英文或中文表头；第一条记录的端口列非数字时也按表头处理。
- 端口为空时默认使用 22。
- 空行、字段不足、Host/User 为空或端口非法的行会跳过，不中断其他行导入。
- 导入数据追加到现有可编辑主机列表；导入后仍可增、删、改。
- CSV 使用 `encoding/csv` 解析，引号包裹的逗号密码可正确读取。
- 建议将导入文件命名为 `targets.hosts.csv`；仓库随附的 `.gitignore` 会忽略 `*.hosts.csv`，降低明文密码误提交风险。

> [!CAUTION]
> CSV 中包含明文密码。请限制文件权限、避免上传或提交到版本控制，并在使用后按组织安全要求妥善处置。

## 5. 规则编写说明

### Rule 字段

| 字段 | 必需 | 说明 |
|---|---:|---|
| `id` | 是 | 规则唯一 ID；外部同 ID 规则覆盖内置规则 |
| `name` | 是 | 英文规则名称 |
| `severity` | 是 | `critical/high/medium/low/info`，输入大小写不敏感，输出归一为小写 |
| `category` | 否 | 风险分类；为空时根据 match 类型推导 |
| `confidence` | 否 | `high/medium/low`，默认 `high` |
| `status` | 否 | `confirmed/suspected/error`，默认 `confirmed` |
| `description` | 否 | 检测说明 |
| `affected.component` | 否 | 受影响组件 |
| `affected.module` | 否 | 受影响模块 |
| `affected.os` | 否 | 受影响 OS |
| `match.type` | 是 | 匹配类型 |
| `match.contains` | 视类型 | 包含匹配文本 |
| `match.path` | 视类型 | SUID 精确路径 |
| `match.os_id` | 视类型 | 期望的 OS ID |
| `match.module` | 视类型 | 内核模块名 |
| `match.modules` | 视类型 | `kernel_cve_module` 的内核模块名列表；任一模块命中即生成一条 finding |
| `match.introduced` | 视类型 | `kernel_version_range` 的可选包含下界 |
| `match.fixed` | 视类型 | `kernel_version_range` 的可选排除上界（第一个安全版本） |
| `reason` | 否 | 命中原因；为空时使用匹配器生成文本 |
| `evidence_template` | 否 | 证据模板，支持 `{{evidence}}`、`{{reason}}` 替换 |
| `impact` | 否 | 影响说明 |
| `condition` | 否 | 利用/风险条件说明 |
| `remediation` | 是 | 修复建议 |
| `false_positive_note` | 否 | 误报说明 |
| `references` | 否 | URL/参考资料列表 |

解析器要求 `id`、`name`、`severity`、`remediation` 和 `match.type` 非空。

### 完整示例

```yaml
rules:
  - id: EXAMPLE-SUDO-NOPASSWD
    name: Example sudo NOPASSWD risk
    severity: high
    category: sudo
    confidence: high
    status: confirmed
    description: Detect NOPASSWD in the current user's sudo policy output.
    match:
      type: sudo_contains
      contains: NOPASSWD
    reason: The sudo policy contains NOPASSWD.
    evidence_template: |
      {{evidence}}
      assessment=read_only
    impact: Allowed commands may provide a privilege escalation path.
    condition: sudo output contains NOPASSWD
    remediation: Minimize sudoers permissions and remove unnecessary NOPASSWD entries.
    false_positive_note: Some tightly scoped automation accounts may require this setting.
    references:
      - https://man7.org/linux/man-pages/man5/sudoers.5.html
```

将文件保存为 `./rules/example.yaml`，或使用：

```bash
./lpe-checker-cli scan --rules /path/to/rules
```

支持 `.yaml` 和 `.yml`。目录中的同 ID 外部规则覆盖内置规则。

> `kernel_cve_module` 规则声明的合法模块名会形成当前扫描实例的封闭采集集合；SSHRunner 只允许查询该集合内模块的固定只读 `find` 形态。其他 match 类型仍必须使用现有采集事实。

## 6. 输出格式

JSON 顶层结构：

```json
{
  "meta": {},
  "target": {},
  "summary": {},
  "system_info": {},
  "checks": [],
  "findings": []
}
```

- `checks`：本次实际评估的检测项。
- `findings`：命中规则后生成的风险记录。
- GUI 只选择部分规则时，未选规则不会进入 `checks` 或 `findings`。

关键英文枚举：

| 对象 | 字段 | 值 |
|---|---|---|
| check | `status` | `completed` / `skipped` / `failed` |
| check | `result` | `found` / `not_found` / `unknown` / `not_applicable` |
| finding | `severity` | `critical` / `high` / `medium` / `low` / `info` |
| finding | `status` | `confirmed` / `suspected` / `error` |
| finding | `confidence` | `high` / `medium` / `low` |

语义：

- 命中：`completed/found`，并生成关联的 finding。
- 未命中：`completed/not_found`，不生成 finding。
- 不适用：`skipped/not_applicable`。
- 依赖的采集项执行失败：`failed/unknown`，`error` 保存失败原因，扫描继续处理其他检测项。
- Finding 的 `check_id` 指向触发它的 check。

JSON 字段名和枚举保持英文；CLI/HTML/GUI 可使用中文展示映射。

## 7. 范围外（不检测）

- `CVE-2026-41651`（PackageKit）：用户态软件包漏洞，不属于内核模块检测；需要软件包版本采集，当前架构不采集。
- `CVE-2026-31635`（rxrpc authenticator）：远程拒绝服务问题，不是本地提权，超出本工具的 LPE 范围。
- `CVE-2026-46243`（CIFSwitch）：暂缓加入。该检测依赖 cifs 模块、cifs-utils、user namespace 与 LSM 等多个外部条件，当前启发式误报风险较高，待模块白名单机制进一步验证后再评估。

## 8. 安全与只读声明

本工具仅进行**只读检测**：仅执行只读采集命令，例如 `uname -r`、`uname -m`、`id`、`sudo -n -l`、`lsmod`、`cat /etc/os-release`、`hostname` 和受限的只读 `find`。本工具不加载或卸载内核模块，不修改任何系统配置，不尝试漏洞利用，也不触发 CVE。

CVE 类检测属于**疑似（suspected）启发式判断**，基于系统版本、模块状态或配置进行只读判断，不能替代厂商安全公告确认。Linux 发行版可能通过 backport 修复漏洞但保留原版本特征，最终结论必须结合厂商公告、软件包 changelog 和人工复核。

SSH 远程扫描只执行固定的只读命令和参数形态白名单，并对每个参数进行 shell 引用；不提供任意命令执行能力。

## 9. 免责声明

本工具仅供对**你拥有合法授权**的主机进行安全自查。

未经授权对他人系统进行扫描、探测或访问可能违反适用的法律法规。使用者应确保获得充分授权，并自行承担使用本工具的全部责任。

作者与贡献者不对任何滥用、误用、未经授权使用或由此产生的直接、间接后果承担责任。

检测结果仅作为安全排查参考，不构成漏洞存在性或可利用性的最终证明。最终结论应结合业务环境、厂商安全公告、软件包状态和人工复核确认。

## 10. 许可证

本项目基于 MIT 许可证，详见 [LICENSE](LICENSE) 文件。 / This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
