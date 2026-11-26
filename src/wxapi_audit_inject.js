(function() {
  if (window._wxApiAuditInjected && window.wxApiAudit) return;
  window._wxApiAuditInjected = true;

  var A = {
    _hooked: false,
    calls: [],
    _maxCalls: 2000,
    _captureRequest: false,
    _captureStorage: false,
    _captureBridge: false,

    _findAllFrames: function() {
      var frames = [];
      var seen = [];
      function tryAdd(w) {
        try {
          if (!w || !w.wx) return;
          for (var i = 0; i < seen.length; i++) { if (seen[i] === w) return; }
          seen.push(w);
          frames.push(w);
        } catch(e) {}
      }
      tryAdd(window);
      var sources = [window];
      try { if (window.parent && window.parent !== window) sources.push(window.parent); } catch(e) {}
      // nav 注入脚本已定位的逻辑层 frame（含完整 wx API）优先纳入
      try {
        if (window.nav && window.nav.wxFrame) tryAdd(window.nav.wxFrame);
      } catch(e) {}
      for (var s = 0; s < sources.length; s++) {
        try {
          var src = sources[s];
          if (src.frames) {
            for (var i = 0; i < src.frames.length; i++) {
              try { tryAdd(src.frames[i]); } catch(e) {}
            }
          }
        } catch(e) {}
      }
      return frames;
    },

    _cfg: function(o) {
      o = o || {};
      A._captureRequest = !!o.captureRequest;
      A._captureStorage = !!o.captureStorage;
      A._captureBridge = !!o.captureBridge;
      return A.install();
    },

    install: function() {
      var frames = A._findAllFrames();
      var hooked = 0;
      for (var i = 0; i < frames.length; i++) {
        try { if (A._hookFrame(frames[i])) hooked++; } catch(e) {}
      }
      A._hooked = hooked > 0;
      return JSON.stringify({ ok: hooked > 0, frames: hooked });
    },

    isHooked: function() { return A._hooked; },

    uninstall: function() {
      for (var i = 0; i < A._origList.length; i++) {
        try { A._origList[i].restore(); } catch(e) {}
      }
      A._origList = [];
      A._hooked = false;
      return JSON.stringify({ ok: true });
    },
    _origList: [],

    _wrap: function(frame, obj, methodName, typeName, filter) {
      try {
        var orig = obj[methodName];
        if (!orig || orig.__wxHooked) return false;
        var wrapped = function() {
          var args = Array.prototype.slice.call(arguments);
          var entry = {
            type: typeName,
            name: methodName,
            ts: Date.now(),
            data: {},
            status: 'pending',
            result: null,
            error: null
          };
          try { entry.data = JSON.parse(JSON.stringify(args.length === 1 ? args[0] : args)); }
          catch(e) { entry.data = { raw: String(args[0]) }; }

          if (filter && !filter(entry, args)) return orig.apply(obj, args);

          var opt = args.length && args[0] && typeof args[0] === 'object' ? args[0] : {};
          var done = false;
          var cb = function(key, statusKey) {
            return function(res) {
              if (done) return; done = true;
              entry.status = statusKey;
              try { entry.result = JSON.parse(JSON.stringify(res)); } catch(e) { entry.result = String(res); }
              A.calls.push(entry);
              if (A.calls.length > A._maxCalls) A.calls.shift();
              if (opt[key]) { try { opt[key](res); } catch(e) {} }
            };
          };
          // 分离 success/fail/complete 回调再调用原函数
          var callArgs = [];
          if (args.length && typeof args[0] === 'object' && args[0] !== null) {
            var copy = {};
            for (var k in args[0]) { copy[k] = args[0][k]; }
            var hasCb = copy.success || copy.fail || copy.complete;
            if (hasCb) {
              copy.success = cb('success', 'success');
              copy.fail = cb('fail', 'fail');
              copy.complete = function(res) {
                if (!done) {
                  done = true;
                  entry.status = entry.status || 'complete';
                  try { entry.result = JSON.parse(JSON.stringify(res)); } catch(e) {}
                  A.calls.push(entry);
                  if (A.calls.length > A._maxCalls) A.calls.shift();
                }
                if (opt.complete) { try { opt.complete(res); } catch(e) {} }
              };
              callArgs.push(copy);
            } else {
              // Promise 风格 (wx.request 无回调时也走这里)
              callArgs.push(copy);
              A._patchPromise(orig.apply(obj, callArgs), entry);
              return;
            }
          } else {
            callArgs = args;
          }
          var ret = orig.apply(obj, callArgs);
          if (!hasCb) A._patchPromise(ret, entry);
          return ret;
        };
        wrapped.__wxHooked = true;
        obj[methodName] = wrapped;
        A._origList.push({ restore: function() { obj[methodName] = orig; } });
        return true;
      } catch(e) { return false; }
    },

    _patchPromise: function(promise, entry) {
      if (!promise || !promise.then) {
        entry.status = 'sync';
        A.calls.push(entry);
        if (A.calls.length > A._maxCalls) A.calls.shift();
        return;
      }
      promise.then(function(res) {
        entry.status = 'success';
        try { entry.result = JSON.parse(JSON.stringify(res)); } catch(e) { entry.result = String(res); }
        A.calls.push(entry);
        if (A.calls.length > A._maxCalls) A.calls.shift();
      })['catch'](function(e) {
        entry.status = 'fail';
        entry.error = e && e.message ? e.message : String(e);
        A.calls.push(entry);
        if (A.calls.length > A._maxCalls) A.calls.shift();
      });
    },

    _hookFrame: function(frame) {
      var wx = frame.wx;
      if (!wx) return false;
      var self = this;

      // 核心身份 API（始终捕获）
      var coreApis = ['login', 'getUserProfile', 'checkSession', 'getSystemInfo',
                      'getAccountInfoSync', 'getAppId', 'getSetting', 'authorize'];
      for (var i = 0; i < coreApis.length; i++) {
        this._wrap(frame, wx, coreApis[i], 'wx.api');
      }

      // 支付
      this._wrap(frame, wx, 'requestPayment', 'wx.pay');

      // wx.request（可选）
      if (this._captureRequest) {
        this._wrap(frame, wx, 'request', 'wx.request', function(entry) {
          var d = entry.data || {};
          entry.name = (d.method || 'GET') + ' ' + (d.url || '');
          return true;
        });
        this._wrap(frame, wx, 'uploadFile', 'wx.request');
        this._wrap(frame, wx, 'downloadFile', 'wx.request');
      }

      // 存储（可选）
      if (this._captureStorage) {
        var st = ['setStorage', 'setStorageSync', 'getStorage', 'getStorageSync',
                  'removeStorage', 'clearStorage', 'getStorageInfo'];
        for (var j = 0; j < st.length; j++) {
          this._wrap(frame, wx, st[j], 'wx.storage');
        }
      }

      // 原生桥接（可选，噪音大）
      if (this._captureBridge && frame.WeixinJSBridge) {
        this._wrap(frame, frame.WeixinJSBridge, 'invoke', 'bridge');
        this._wrap(frame, frame.WeixinJSBridge, 'on', 'bridge.on');
      }

      return true;
    },

    getCalls: function() { return JSON.stringify(A.calls); },
    clear: function() { A.calls = []; return JSON.stringify({ ok: true }); }
  };

  if (!window.wxApiAudit) window.wxApiAudit = A;
})();
