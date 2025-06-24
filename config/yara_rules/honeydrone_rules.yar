rule Suspicious_Base64 {
    strings:
        $base64_long = /[A-Za-z0-9+\/]{100,}={0,2}/
        $base64_encoded = "base64"
    condition:
        $base64_long and $base64_encoded
}

rule Shell_Commands {
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/bin/sh" nocase
        $cmd3 = "/bin/bash" nocase
        $cmd4 = "powershell" nocase
    condition:
        any of them
}

rule Network_Reconnaissance {
    strings:
        $nmap = "nmap" nocase
        $scan = "port scan" nocase
        $enum = "enum" nocase
        $recon = "reconnaissance" nocase
    condition:
        any of them
}

rule Persistence_Mechanisms {
    strings:
        $cron = "crontab" nocase
        $service = "systemctl" nocase
        $startup = "autostart" nocase
        $registry = "HKEY_" nocase
    condition:
        any of them
}

rule MAVLink_Attack {
    strings:
        $mavlink_magic = { FE }
        $mavlink_heartbeat = { 00 00 00 00 00 00 }
        $mavlink_command = { 4C 00 00 00 }
    condition:
        $mavlink_magic at 0 and any of ($mavlink_heartbeat, $mavlink_command)
}

rule Drone_Exploitation {
    strings:
        $ardupilot = "ArduPilot" nocase
        $mavproxy = "MAVProxy" nocase
        $qgroundcontrol = "QGroundControl" nocase
        $exploit = "exploit" nocase
    condition:
        any of them
}