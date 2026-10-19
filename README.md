# VirtBootFix

安全启动 + CPU 虚拟化 检测/设置工具（国服 / 港服双模式）。检测出未设置的项时，提供 **0-4 数字选择**处理。Python 标准库实现，无第三方依赖。

Secure Boot + CPU Virtualization detect & fix tool with CN / HK server modes. Unset items offer **numeric choices 0-4**. Python stdlib only.

## 检测项 / Check items

| # | 项目 / Item | 说明 / Description |
| --- | --- | --- |
| 01 | 开启UEFI启动 / UEFI boot | 固件需为 UEFI 模式（Legacy 需重装转换） |
| 02 | 磁盘格式为GPT / GPT disk | 系统盘分区表需为 GPT（可 mbr2gpt 转换） |
| 03 | 开启TPM2.0 / TPM 2.0 | TPM 2.0（BIOS 里 fTPM / Intel PTT） |
| 04 | 开启安全启动 / Secure Boot | BIOS 里的 Secure Boot |
| 05 | 开启CPU虚拟化 / Virtualization | Intel VT-x / AMD SVM |
| 06 | HVCI内存完整性 / Memory integrity | 内核隔离 - 内存完整性（注册表可改） |
| 07 | VBS内核隔离 / VBS | 基于虚拟化的安全（注册表可改） |
| 08 | HyperV服务 / Hyper-V | hypervisor 启动类型（bcdedit 可改） |

## 两种模式 / Two modes

| 模式 / Mode | 适用 / For | 目标状态 / Target |
| --- | --- | --- |
| 1 国服修复 / CN fix | ACE 报错、WeGame / 无畏契约国服 | 虚拟化 **开**，HVCI / VBS / Hyper-V **关** |
| 2 港服修复 / HK fix | Riot 平台（Vanguard）：TPM 2.0 / Secure Boot / HVCI 报错 | 虚拟化、HVCI、VBS 全 **开** |
| 3 逐项自定义 / custom | 任意组合 / any combination | 每项单独决定 开/关 |

## 未设置项的选择 / Choices for unset items

| 输入 / Input | 动作 / Action |
| --- | --- |
| 0 | 跳过 / skip |
| 1 | 自动设置（BIOS 项给出指引）/ auto-fix (BIOS items: guidance) |
| 2 | 打开相关设置（tpm.msc / 磁盘管理 / 内核隔离页 / 重启进 UEFI）/ open related settings |
| 3 | 查看该项说明 / show info |
| 4 | 本项及剩余未达标项全部自动设置 / auto-fix this and all remaining |

## 用法 / Usage

```powershell
py virt_boot_fix.py
```

启动时自动请求管理员权限（UAC）。检测 → 选模式 → 对未达标项逐个输入 0-4 → 自动复检并汇总；涉及注册表 / bcdedit 的改动会提示重启生效，可直接选择重启。

Admin (UAC) is requested on launch. Detect → choose mode → answer 0-4 per unset item → automatic re-check and summary; registry / bcdedit changes require a reboot (the tool offers to do it).

> 注意 / Note: UEFI / GPT / TPM / Secure Boot / CPU 虚拟化属于固件设置，Windows 内无法直接修改，工具会给出 BIOS 操作指引并支持「重启进入 UEFI 固件」（`shutdown /r /fw`）。MBR→GPT 转换（mbr2gpt）为风险操作，需再次确认才会执行。
> Note: firmware-level items cannot be changed from Windows; the tool prints BIOS guidance and can reboot into UEFI firmware (`shutdown /r /fw`). The MBR→GPT conversion (mbr2gpt) is risky and asks for confirmation.

## 依赖 / Dependencies

仅 Python 标准库 / stdlib only. 用 **`py`** 启动器运行 / run with the **`py`** launcher.

## 更新记录 / Changelog

- **修复检测全崩**：主流程函数名 `run` 与命令执行函数 `run(cmd, timeout)` 重名，Python 后定义覆盖前者，导致所有检测项报 `detect error: run() takes 0 positional arguments`。已将主流程重命名为 `main()`。若此前打开后"什么都检测不到"，更新后即可正常。
- **必须以管理员运行**：TPM / Secure Boot / 磁盘分区 / bcdedit 等检测需要管理员权限。双击运行时**务必在 UAC 弹窗点「是」**；若未提权，这几项会读不到（显示「未知 / 需先开启 UEFI」），并非工具失效。
- **Fix detection crash**: the main routine was named `run`, colliding with the command runner `run()`; renamed to `main()`. Run **as administrator** (approve UAC) so TPM / Secure Boot / disk / bcdedit can be read.
