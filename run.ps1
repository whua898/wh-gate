# ProtonVPN 下载脚本
$env:PROTON_USER = "tzhua898"
$env:PROTON_PASS = "whua89pt89"
$env:PROTON_ENC_KEY = "96syrIk11ZZrzikxU4DBPsAY_OxK6UT9F4jaKGouDI8="
$env:PROTON_CERT_PURGE = "1"  # 首次清理设为 "1"，之后改回 "0"

cd $PSScriptRoot
.venv\Scripts\python.exe proton_downloader.py
