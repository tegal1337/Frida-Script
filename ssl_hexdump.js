// ssl_hexdump.js — minimal SSL hooks, full hex capture of all XL API frames
// No Java. No ALPN changes. Only native SSL hooks — same as ssl_raw.js that worked.

console.log('[*] ssl_hexdump.js starting');

function findExport(sym) {
  var m = Process.findModuleByName('libssl.so');
  if(m){ try{ var e=m.findExportByName(sym); if(e) return e; }catch(_){} }
  return null;
}

// buf → hex string
function toHex(ptr, len) {
  var n = Math.min(len, 8192); // capture up to 8KB per call
  var hex = '';
  for(var i=0; i<n; i++){
    try{ var b=ptr.add(i).readU8(); hex += (b<16?'0':'')+b.toString(16); }catch(_){ break; }
  }
  return hex;
}

// buf → readable ASCII (for console logging)
function toAscii(ptr, len) {
  var n = Math.min(len, 200);
  try{ return ptr.readUtf8String(n); }catch(e){
    var s='';
    for(var i=0;i<Math.min(n,80);i++){
      try{ var b=ptr.add(i).readU8(); s+=(b>=32&&b<127)?String.fromCharCode(b):'.'; }catch(_){ break; }
    }
    return s;
  }
}

// SNI mapping
var sslHostmap = {};
var STSHN = findExport('SSL_set_tlsext_host_name');
if(STSHN){
  Interceptor.attach(STSHN, {
    onEnter: function(a){
      try{ var h=a[1].readUtf8String(); if(h) sslHostmap[a[0].toString()]=h; }catch(_){}
    }
  });
  console.log('[OK] SNI hook');
}

function getHost(sslPtr) {
  return sslHostmap[sslPtr.toString()] || '?';
}

function isXL(host) {
  return host.indexOf('xl.co.id')>=0 || host.indexOf('axiapp')>=0 ||
         host.indexOf('xlaxiata')>=0 || host.indexOf('vkey')>=0 ||
         host.indexOf('srg-axiapp')>=0;
}

var wN=0, rN=0;

// SSL_write — capture outgoing
var SSL_write = findExport('SSL_write');
if(SSL_write){
  Interceptor.attach(SSL_write, {
    onEnter: function(a){ this.ssl=a[0]; this.buf=a[1]; this.len=a[2].toInt32(); },
    onLeave: function(ret){
      if(ret.toInt32()<=0||!this.buf||this.buf.isNull()) return;
      var host=getHost(this.ssl);
      wN++;
      var preview=toAscii(this.buf,this.len);
      console.log('[W#'+wN+' '+host+' '+this.len+'b] '+preview.substring(0,100));
      // Send full hex for ALL connections (needed for HTTP/2 decode)
      var hex=toHex(this.buf,this.len);
      send({t:'W',n:wN,host:host,len:this.len,hex:hex});
    }
  });
  console.log('[OK] SSL_write hook');
}

// SSL_read — capture incoming
var SSL_read = findExport('SSL_read');
if(SSL_read){
  Interceptor.attach(SSL_read, {
    onEnter: function(a){ this.ssl=a[0]; this.buf=a[1]; },
    onLeave: function(ret){
      var n=ret.toInt32();
      if(n<=0||!this.buf||this.buf.isNull()) return;
      var host=getHost(this.ssl);
      rN++;
      var preview=toAscii(this.buf,n);
      console.log('[R#'+rN+' '+host+' '+n+'b] '+preview.substring(0,100));
      if(isXL(host)){
        var hex=toHex(this.buf,n);
        send({t:'R',n:rN,host:host,len:n,hex:hex});
      }
    }
  });
  console.log('[OK] SSL_read hook');
}

console.log('[*] ssl_hexdump.js READY');
send({t:'READY'});
