@echo off

for /l %%i in (1,1,100) do (
    echo ================= RUN %%i =================

    echo Stopping dnscrypt-proxy...
    taskkill /IM dnscrypt-proxy.exe /F >nul 2>&1

    echo Flushing DNS...
    ipconfig /flushdns

    echo Starting dnscrypt-proxy...
    start "" "dnscrypt-proxy.exe"

    echo Running Python test...
    python test_dns.py

    timeout /t 2 >nul
)
