import subprocess
import json
from datetime import datetime

def get_real_windows_logs(max_events=50):
    powershell_cmd = """
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security';
        Id = 4624,4625,4740,4720,4648,4688
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    $results = @()
    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) {
            if ($item.Name) { $data[$item.Name] = $item.'#text' }
        }
        $results += @{
            event_id = $event.Id.ToString()
            timestamp = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            source_ip = if ($data['IpAddress']) { $data['IpAddress'] } else { '127.0.0.1' }
            username = if ($data['TargetUserName']) { $data['TargetUserName'] } else { 'Unknown' }
            computer = $event.MachineName
        }
    }
    $results | ConvertTo-Json -Depth 3
    """
    try:
        result = subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', powershell_cmd],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        events = json.loads(result.stdout.strip())
        if isinstance(events, dict):
            events = [events]
        severity_map = {'4624':'Low','4625':'Medium','4740':'High','4720':'High','4648':'High','4688':'Low'}
        type_map = {'4624':'Successful Login','4625':'Failed Login','4740':'Account Lockout','4720':'New User Created','4648':'Login With Explicit Credentials','4688':'Process Started'}
        logs = []
        for i, event in enumerate(events):
            eid = str(event.get('event_id', '0'))
            ip = event.get('source_ip', '127.0.0.1')
            if ip in ['-', '', None]:
                ip = '127.0.0.1'
            logs.append({
                "id": i + 1,
                "timestamp": event.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "event_id": eid,
                "type": type_map.get(eid, 'Unknown Event'),
                "severity": severity_map.get(eid, 'Low'),
                "source_ip": ip,
                "username": event.get('username', 'Unknown'),
                "computer": event.get('computer', 'localhost'),
                "status": "Open"
            })
        return logs
    except Exception as e:
        print(f"Windows log error: {e}")
        return None