#!/usr/bin/env python3
# virt_boot_fix.py
# 安全启动 + CPU 虚拟化 检测/设置工具（国服 / 港服双模式）。
# Secure Boot + CPU Virtualization detect & fix tool (CN / HK server modes).
# 检测出未设置的项时，提供 0-4 数字选择处理 / Unset items offer choices 0-4.
#
# 用法 / Usage:
#   py virt_boot_fix.py
#
# 依赖 / Dependencies: 仅标准库 / stdlib only.

import os
import re
import sys
import time
import ctypes
import winreg
import subprocess

REBOOT_FLAG = {"need": False}


# ----------------------------- 基础 / Basics -----------------------------

def run(cmd, timeout=60):
    """执行命令（GBK 解码）/ Run a command, GBK-decoded."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        r.text = (r.stdout or b"").decode("gbk", "replace")
        return r
    except Exception as e:
        class R:
            returncode, text = 1, str(e)
        return R()


def ps(script, timeout=90):
    """执行 PowerShell 单行 / Run a PowerShell one-liner."""
    return run(["powershell", "-NoProfile", "-Command", script], timeout)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def try_elevate():
    """请求管理员权限（UAC）/ Request admin via UAC."""
    if is_admin():
        return True
    args = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            f'"{os.path.abspath(__file__)}" {args}', None, 1)
    except Exception:
        ret = -1
    if ret > 32:
        sys.exit(0)
    print("⚠ 未获得管理员权限，部分设置无法执行 / not admin, some fixes disabled")
    return False


def reg_get(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        v, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return v
    except OSError:
        return None


def reg_set(path, name, value):
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


def reboot_to_firmware_ok():
    """UEFI 系统才能「重启进固件」/ reboot-to-firmware only on UEFI."""
    return ps("$env:firmware_type").text.strip().lower() == "uefi"


def ask_reboot_firmware():
    if reboot_to_firmware_ok() and input(
            "  现在重启进入 BIOS/UEFI？(y/N) / reboot into firmware now? ").strip().lower() == "y":
        os.system("shutdown /r /fw /t 5")
        sys.exit(0)


# ----------------------------- 检测 / Detection -----------------------------
# 每项返回 (状态 True/False/None, 说明) / (state, detail)

def detect_uefi():
    t = ps("$env:firmware_type").text.strip().lower()
    if t == "uefi":
        return True, "UEFI"
    if t == "legacy":
        return False, "Legacy BIOS"
    return None, "未知 / unknown"


def detect_gpt():
    r = ps("(Get-Disk | Where-Object IsBoot | Select-Object -First 1).PartitionStyle")
    t = r.text.strip()
    if t == "GPT":
        return True, "GPT"
    if t == "MBR":
        return False, "MBR"
    return None, t or "未知 / unknown"


def detect_tpm_real():
    r = ps('$t=Get-Tpm; $s=(Get-CimInstance -Namespace "root/cimv2/Security/MicrosoftTpm" '
           '-ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecificationVersion; '
           'Write-Output ("{0}|{1}|{2}" -f $t.TpmPresent, $t.TpmReady, $s)')
    parts = r.text.strip().split("|")
    present = parts[0].lower() == "true" if len(parts) > 0 else False
    spec = parts[2].strip() if len(parts) > 2 else ""
    if not present:
        return False, "无 TPM 设备 / no TPM device"
    if spec.startswith("2."):
        return True, f"TPM {spec}"
    return False, f"TPM 版本 {spec or '?'}（需 2.0）"


def detect_secureboot():
    r = ps("Confirm-SecureBootUEFI")
    t = r.text.strip().lower()
    if t == "true":
        return True, "已开启 / enabled"
    if t == "false":
        return False, "未开启 / disabled"
    return None, "需先开启 UEFI / requires UEFI"


def detect_vt():
    r = ps('(Get-CimInstance Win32_ComputerSystem).HypervisorPresent; '
           '(Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled')
    lines = [x.strip().lower() for x in r.text.splitlines() if x.strip()]
    if "true" in lines:
        return True, "虚拟化已启用 / enabled"
    return False, "未启用（需在 BIOS 开启）/ disabled (BIOS)"


def detect_hvci():
    v = reg_get(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                r"\HypervisorEnforcedCodeIntegrity", "Enabled")
    if v == 1:
        return True, "已开启 / enabled"
    return False, "未开启 / disabled"


def detect_vbs():
    v = reg_get(r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity")
    if v == 1:
        return True, "已开启 / enabled"
    return False, "未开启 / disabled"


def detect_hyperv():
    r = run(["bcdedit", "/enum", "{current}"])
    if re.search(r"hypervisorlaunchtype\s+Off", r.text, re.I):
        return False, "hypervisorlaunchtype Off"
    return True, "hypervisor 运行中 / running"


# ----------------------------- 设置 / Fixers -----------------------------
# 返回 (是否成功, 说明) / (ok, msg)

def fix_hvci(target):
    ok = reg_set(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                 r"\HypervisorEnforcedCodeIntegrity", "Enabled", 1 if target else 0)
    REBOOT_FLAG["need"] = True
    return ok, ("已写入注册表，重启生效 / registry set, reboot needed")


def fix_vbs(target):
    ok = reg_set(r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                 "EnableVirtualizationBasedSecurity", 1 if target else 0)
    REBOOT_FLAG["need"] = True
    return ok, ("已写入注册表，重启生效 / registry set, reboot needed")


def fix_hyperv(target):
    val = "auto" if target else "off"
    r = run(["bcdedit", "/set", "hypervisorlaunchtype", val])
    REBOOT_FLAG["need"] = True
    return r.returncode == 0, f"hypervisorlaunchtype={val}，重启生效 / reboot needed"


def fix_gpt_convert():
    """MBR→GPT（mbr2gpt，风险操作需确认）/ Convert MBR to GPT via mbr2gpt."""
    r = run(["mbr2gpt", "/validate", "/allowFullOS"], timeout=120)
    if r.returncode != 0:
        return False, "校验未通过，无法安全转换 / validation failed"
    if input("  校验通过。确认转换 MBR→GPT？风险操作！(y/N) / confirm convert? ").lower() != "y":
        return False, "已取消 / cancelled"
    r = run(["mbr2gpt", "/convert", "/allowFullOS"], timeout=600)
    REBOOT_FLAG["need"] = True
    return r.returncode == 0, "已转换，重启生效 / converted, reboot needed"


GUIDE_BIOS = ("该项只能在主板 BIOS/UEFI 里设置，Windows 无法直接改：\n"
              "  重启按 Del/F2 进 BIOS → 找 Secure Boot / TPM (fTPM、PTT) / "
              "Intel VT-x (VT-d) / SVM → 设为 Enabled 保存。\n"
              "  Set it in BIOS: enable Secure Boot / TPM (fTPM, PTT) / VT-x (SVM).")


# 项目表：key / 中文 / 英文 / 检测 / 目标(国服, 港服) / 自动修复 / 打开设置
ITEMS = [
    dict(key="uefi",   zh="开启UEFI启动",        en="UEFI boot",
         detect=detect_uefi, targets=(True, True), fix=None,
         open="bios", desc="固件需为 UEFI 模式 / firmware must be UEFI"),
    dict(key="gpt",    zh="磁盘格式为GPT",       en="GPT disk",
         detect=detect_gpt, targets=(True, True), fix="mbr2gpt",
         open="diskmgmt", desc="系统盘分区表需为 GPT / boot disk must be GPT"),
    dict(key="tpm",    zh="开启TPM2.0",          en="TPM 2.0",
         detect=detect_tpm_real, targets=(True, True), fix=None,
         open="tpmmsc", desc="TPM 2.0 需在 BIOS 开启 / enable in BIOS (fTPM/PTT)"),
    dict(key="sb",     zh="开启安全启动",         en="Secure Boot",
         detect=detect_secureboot, targets=(True, True), fix=None,
         open="bios", desc="Secure Boot 需在 BIOS 开启 / enable in BIOS"),
    dict(key="vt",     zh="开启CPU虚拟化",        en="CPU virtualization",
         detect=detect_vt, targets=(True, True), fix=None,
         open="bios", desc="VT-x / SVM 需在 BIOS 开启 / enable VT-x or SVM in BIOS"),
    dict(key="hvci",   zh="HVCI内存完整性",       en="HVCI memory integrity",
         detect=detect_hvci, targets=(False, True), fix=fix_hvci,
         open="coreiso", desc="内核隔离-内存完整性 / core isolation"),
    dict(key="vbs",    zh="VBS内核隔离",          en="VBS",
         detect=detect_vbs, targets=(False, True), fix=fix_vbs,
         open="coreiso", desc="基于虚拟化的安全 / virtualization-based security"),
    dict(key="hyperv", zh="HyperV服务",           en="Hyper-V",
         detect=detect_hyperv, targets=(False, True), fix=fix_hyperv,
         open="optfeat", desc="hypervisor 启动类型 / hypervisor launch type"),
]


def detect_all():
    states = []
    for it in ITEMS:
        try:
            st, detail = it["detect"]()
        except Exception as e:
            st, detail = None, f"检测失败 / detect error: {e}"
        states.append((st, detail))
    return states


# ----------------------------- 界面 / UI -----------------------------

MARK = {True: "已完成 Done", False: "未设置 Not set", None: "未知 Unknown"}


def print_table(states):
    print()
    print("───── 安全启动状态检测 / Secure Boot status ─────")
    for i in range(4):
        st, detail = states[i]
        print(f"  {i+1:02d}  {ITEMS[i]['zh']} / {ITEMS[i]['en']:<20} [{MARK[st]}]  {detail}")
    print()
    print("───── CPU 虚拟化检测 / Virtualization status ─────")
    for i in range(4, 8):
        st, detail = states[i]
        print(f"  {i+1:02d}  {ITEMS[i]['zh']} / {ITEMS[i]['en']:<20} [{MARK[st]}]  {detail}")
    print()
    boot_ok = all(states[i][0] is True for i in range(4))
    if boot_ok:
        print("✔ 已开启安全启动，请尽情享受游戏！/ Secure Boot ready — enjoy!")
    else:
        print("✖ 尚有安全启动项未完成 / some Secure Boot items incomplete")
    print()


CHOICE_MENU = ("  选择 / choose  [0]跳过 skip  [1]自动设置 auto-fix  "
               "[2]打开相关设置 open  [3]说明 info  [4]剩余全部 auto-rest : ")


def open_item(idx):
    """选择 2：打开相关设置页 / open the related settings page."""
    where = ITEMS[idx]["open"]
    if where == "bios":
        ask_reboot_firmware()
        print("  无法直接改 BIOS，请重启进固件设置 / BIOS must be set manually")
    elif where == "tpmmsc":
        os.system("start tpm.msc")
    elif where == "diskmgmt":
        os.system("start diskmgmt.msc")
    elif where == "optfeat":
        os.system("start optionalfeatures.exe")
    elif where == "coreiso":
        try:
            os.startfile("ms-settings:deviceguard")
        except OSError:
            os.startfile("ms-settings:windowsdefender")


def apply_item(idx, target, auto_rest):
    """处理一个未达标项 / handle one item that doesn't meet the target."""
    it = ITEMS[idx]
    while True:
        choice = input(CHOICE_MENU).strip()
        if choice == "0":
            return auto_rest
        if choice == "4":
            auto_rest = True
        if choice in ("1", "4"):
            fix = it["fix"]
            if fix == "mbr2gpt":
                ok, msg = fix_gpt_convert()
            elif fix is not None:
                ok, msg = fix(target)
            else:
                print("  该项无法在系统内自动设置 / cannot auto-fix from Windows")
                print("  " + GUIDE_BIOS)
                ask_reboot_firmware()
                return auto_rest
            print(f"  -> {msg}")
            if choice == "1":
                return auto_rest
        elif choice == "2":
            open_item(idx)
            return auto_rest
        elif choice == "3":
            print(f"  说明 / info: {it['desc']}")
            if it["fix"] is None:
                print("  " + GUIDE_BIOS)
        else:
            print("  无效输入 / invalid input")


def idx_key_target(idx):
    """给 fix_hvci/fix_vbs/fix_hyperv 的占位参数 / placeholder first arg."""
    return 0


def auto_apply(idx, target):
    """自动应用一个可修复项 / auto-apply a fixable item."""
    it = ITEMS[idx]
    fix = it["fix"]
    if fix == "mbr2gpt":
        print(f"  [{idx+1:02d}] MBR→GPT 转换风险大，跳过（可稍后单独选 1 执行）/ "
              f"risky convert skipped")
        return
    if fix is None:
        print(f"  [{idx+1:02d}] {it['zh']} 需在 BIOS 手动开启，跳过 / BIOS-only, skipped")
        return
    ok, msg = fix(target)
    print(f"  [{idx+1:02d}] {it['zh']} / {it['en']} -> {msg}")


def choose_mode():
    print("选择修复模式 / choose fix mode：")
    print("  1 = 国服修复（ACE / WeGame：虚拟化开，HVCI/VBS/HyperV 关）")
    print("      CN server fix: virtualization ON, HVCI/VBS/Hyper-V OFF")
    print("  2 = 港服修复（Riot / Vanguard：虚拟化/HVCI/VBS 全开）")
    print("      HK server fix: virtualization, HVCI, VBS all ON")
    print("  3 = 逐项自定义 / item-by-item custom")
    print("  0 = 退出 / exit")
    while True:
        c = input("请输入 / enter [0-3]: ").strip()
        if c in ("0", "1", "2", "3"):
            return int(c)
        print("  无效输入 / invalid input")


def mode_index(mode):
    """模式在 targets 元组里的下标 / index into targets tuple."""
    return 0 if mode == 1 else 1


def main():
    print("=" * 62)
    print("  安全启动 + CPU 虚拟化 检测/设置工具")
    print("  Secure Boot + Virtualization Detect & Fix Tool")
    print("=" * 62)

    states = detect_all()
    print_table(states)

    mode = choose_mode()
    if mode == 0:
        return

    auto_rest = False
    for i, it in enumerate(ITEMS):
        target = (True if mode in (1, 2) else None) if i < 4 else \
                 it["targets"][mode_index(mode)]
        if mode == 3:
            target = None  # 逐项模式由用户决定 / decided per item below
        st = states[i][0]
        if mode != 3 and st == target:
            continue
        if mode == 3:
            want = input(f"  {it['zh']} / {it['en']} 设为 开(1)/关(0)/跳过(Enter): ").strip()
            if want not in ("0", "1"):
                continue
            target = want == "1"
            if st == target:
                continue
        if auto_rest:
            # 选择 4 之后：剩余未达标项全部自动处理 / auto-fix the rest
            auto_apply(i, target)
            continue
        print(f"\n  [{i+1:02d}] {it['zh']} / {it['en']} —— 当前 {MARK[st]}，目标 "
              f"{'开启 ON' if target else '关闭 OFF'}")
        auto_rest = apply_item(i, target, auto_rest)

    # 复检 / re-detect
    print("\n───── 复检结果 / Re-check ─────")
    states2 = detect_all()
    print_table(states2)
    if REBOOT_FLAG["need"]:
        print("⚠ 部分设置需重启电脑后生效 / some settings need a reboot")
        if input("  现在重启？(y/N) / reboot now? ").strip().lower() == "y":
            os.system("shutdown /r /t 5")


if __name__ == "__main__":
    try_elevate()
    try:
        main()
    except KeyboardInterrupt:
        print("\n退出 / aborted")
