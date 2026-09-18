// hook_template.js — Frida hooks for the vivo Office Kit Windows client.
//
// Run in the Windows 11 guest (no privilege gymnastics needed there):
//   frida -l hook_template.js -f "C:\\path\\to\\vivoOfficeKit.exe"   # spawn
//   frida -l hook_template.js "vivoOfficeKit"                        # attach
//
// Goal: read the PLAINTEXT protocol by hooking send/recv and the crypto calls,
// without ever breaking the encryption. Both endpoints speak the same protocol,
// so instrumenting the client is equivalent to instrumenting the phone.
//
// CLEAN-ROOM NOTE: what you learn here goes into protocol/PROTOCOL.md, not
// copy-pasted into src/.

'use strict';

function hexdump_arg(ptr, len) {
  try {
    return hexdump(ptr, { length: Math.min(len, 512), ansi: false });
  } catch (e) {
    return '<unreadable: ' + e + '>';
  }
}

// ── Winsock: the raw wire (post-encryption on send, pre-decryption on recv) ──
['send', 'recv'].forEach(function (name) {
  const p = Module.findExportByName('ws2_32.dll', name);
  if (!p) { console.log('[!] ws2_32.dll!' + name + ' not found'); return; }
  Interceptor.attach(p, {
    onEnter(args) { this.buf = args[1]; this.len = args[2].toInt32(); },
    onLeave(ret) {
      const n = name === 'recv' ? ret.toInt32() : this.len;
      if (n > 0) {
        console.log('\n=== ' + name + ' (' + n + ' bytes) ===');
        console.log(hexdump_arg(this.buf, n));
      }
    },
  });
});

// ── CNG crypto: plaintext BEFORE encrypt / AFTER decrypt ────────────────────
// BCryptEncrypt / BCryptDecrypt live in bcrypt.dll. pbInput is arg index 1.
['BCryptEncrypt', 'BCryptDecrypt'].forEach(function (name) {
  const p = Module.findExportByName('bcrypt.dll', name);
  if (!p) { console.log('[!] bcrypt.dll!' + name + ' not found'); return; }
  Interceptor.attach(p, {
    onEnter(args) {
      const cb = args[2].toInt32();
      if (cb > 0) {
        console.log('\n=== ' + name + ' plaintext-side (' + cb + ' bytes) ===');
        console.log(hexdump_arg(args[1], cb));
      }
    },
  });
});

// TODO once PROTOCOL.md progresses:
//  - hook the app's own encrypt/decrypt wrappers (find via strings/IDA) for
//    cleaner framing boundaries than the CNG layer.
//  - if Electron: skip Frida — unpack app.asar and read the JS.
//  - if Qt/QML: extract the QML resources instead.
console.log('[*] vivo-linkkit hooks installed.');
