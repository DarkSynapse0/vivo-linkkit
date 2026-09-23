// frida_upload_hook.js — dump the official Office Kit client's plaintext file-upload
// request BEFORE TLS encryption, to recover the drop_file_to_phone body framing that
// SSLKEYLOGFILE couldn't (the bytes go over Node/OpenSSL, not Chromium). PROTOCOL §7.
//
// Drive from the host against the VM's frida-server:
//   frida -H <vm-ip>:27042 -n "<office-kit main proc>" -l scripts/vm/frida_upload_hook.js
// then send ONE small file in Office Kit and read the dumped request here.

'use strict';

var MARKERS = ['drop_file_to_phone', 'upload_files', 'drop_files_info',
               '/upload/', 'get_path', 'file_check', 'upload_files_info',
               'POST /', 'PUT /', 'HTTP/1.', 'Host:'];
var DIAG_LEFT = 12;   // dump the first N TLS writes unconditionally (to see the traffic)

function interesting(s) {
  for (var i = 0; i < MARKERS.length; i++) if (s.indexOf(MARKERS[i]) >= 0) return true;
  return false;
}

// read up to `len` bytes as latin1 so binary body doesn't abort the decode
function readText(buf, len) {
  var n = Math.min(len, 8192);
  try {
    var arr = new Uint8Array(buf.readByteArray(n));
    var s = '';
    for (var i = 0; i < arr.length; i++) {
      var c = arr[i];
      s += (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ? String.fromCharCode(c) : '.';
    }
    return s;
  } catch (e) { return ''; }
}

function dump(fn, mod, buf, len) {
  var s = readText(buf, len);
  if (!s) return;
  if (interesting(s)) {
    send({ kind: 'upload', fn: fn, mod: mod, len: len, data: s.slice(0, 3000) });
  } else if (DIAG_LEFT > 0) {
    DIAG_LEFT--;
    send({ kind: 'diag', fn: fn, mod: mod, len: len, data: s.slice(0, 120) });
  }
}

var hooked = 0;
['SSL_write', 'SSL_write_ex'].forEach(function (name) {
  Process.enumerateModules().forEach(function (m) {
    var addr = null;
    try { addr = Module.findExportByName(m.name, name); } catch (e) {}
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        // SSL_write(ssl, buf, num) / SSL_write_ex(ssl, buf, num, *written)
        try { dump(name, m.name, args[1], args[2].toInt32()); } catch (e) {}
      }
    });
    hooked++;
    console.log('[hook] ' + name + ' @ ' + m.name);
  });
});
// --- Windows Schannel: EncryptMessage(phContext, fQOP, pMessage, seqNo) ---
// vivorelay.exe (native Poco) uses Schannel, so SSLKEYLOGFILE never saw the bytes.
// The plaintext lives in the SECBUFFER_DATA (type 1) buffer of pMessage before encryption.
(function () {
  var addr = null;
  try { addr = Module.getGlobalExportByName('EncryptMessage'); } catch (e) {}
  if (!addr) { try { addr = Module.findExportByName(null, 'EncryptMessage'); } catch (e) {} }
  if (!addr) { console.log('[hook] EncryptMessage not found'); return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        var pMessage = args[2];               // PSecBufferDesc
        var cBuffers = pMessage.add(4).readU32();
        var pBuffers = pMessage.add(8).readPointer();
        for (var i = 0; i < cBuffers; i++) {
          var sb = pBuffers.add(i * 16);      // SecBuffer{cbBuffer(4),BufferType(4),pvBuffer(8)}
          var cb = sb.readU32();
          var type = sb.add(4).readU32();
          var pv = sb.add(8).readPointer();
          if (type === 1 /*SECBUFFER_DATA*/ && cb > 0 && !pv.isNull()) {
            dump('EncryptMessage', 'Schannel', pv, cb);
          }
        }
      } catch (e) {}
    }
  });
  hooked++;
  console.log('[hook] EncryptMessage @ ' + addr);
})();

console.log('[frida_upload_hook] attached ' + hooked + ' hook(s). Now send a file in Office Kit.');
