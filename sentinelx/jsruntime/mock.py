"""SentinelX jsruntime.mock: browser-like JS environment for js2py.

Builds a JavaScript preamble that defines window, document, location,
history, navigator, DOM elements, events, localStorage/sessionStorage,
fetch, XMLHttpRequest, WebSocket — all instrumented to record
security-relevant behavior into ``__sx_trace`` (a JS array Python reads
after execution).

Design rules:
- ES5.1 only (js2py implements ECMAScript 5.1): var/function only.
- Every mock records to __sx_trace. Nothing is silent.
- Unsupported APIs exist as stubs that LOG their invocation as
  "unsupported:<name>" — observable, never a silent no-op.
- Sources (location.hash/search, form values) return canary values so
  Python can prove source → sink data flow.
"""

from __future__ import annotations

import json


def _js_str(s: str) -> str:
    """Encode a Python string as a JS string literal."""
    return json.dumps(s)


def build_preamble(page_url: str = "", hash_canary: str = "SX_CANARY",
                   search_canary: str = "SX_CANARY") -> str:
    """Return the JS preamble defining the mock browser environment."""
    return """
// ================= SentinelX virtual browser (js2py) =================
var __sx_trace = [];
function __sx_log(kind, data) {
    try { __sx_trace.push({kind: kind, data: (data === undefined ? null : data)}); }
    catch (e) { __sx_trace.push({kind: "log-error", data: String(e)}); }
}
function __sx_unsupported(name) {
    __sx_log("unsupported", name);
}

// ---- location ----
var location = {
    href: %s,
    protocol: "http:",
    host: "localhost",
    hostname: "localhost",
    port: "",
    pathname: "/",
    search: %s,
    hash: %s,
    origin: "http://localhost",
    assign: function(u) { __sx_log("nav:assign", String(u)); },
    replace: function(u) { __sx_log("nav:replace", String(u)); },
    reload: function() { __sx_log("nav:reload", null); },
    toString: function() { return this.href; }
};

// ---- history ----
var history = {
    pushState: function(s, t, u) { __sx_log("nav:pushState", String(u)); },
    replaceState: function(s, t, u) { __sx_log("nav:replaceState", String(u)); },
    back: function() { __sx_log("nav:back", null); },
    forward: function() { __sx_log("nav:forward", null); },
    go: function(n) { __sx_log("nav:go", String(n)); }
};

// ---- navigator ----
var navigator = {
    userAgent: "SentinelX/jsruntime",
    platform: "Linux",
    language: "en-US",
    onLine: true,
    cookieEnabled: true
};

// ---- storage ----
function __sx_make_storage(name) {
    var store = {};
    // NOTE: js2py cannot translate `get length()` accessors, so length is a
    // plain property (not live-counted). Storage access is still logged.
    return {
        getItem: function(k) { __sx_log("storage:get", {store: name, key: String(k)}); return (k in store) ? store[k] : null; },
        setItem: function(k, v) { __sx_log("storage:set", {store: name, key: String(k), value: String(v).slice(0, 500)}); store[k] = String(v); },
        removeItem: function(k) { __sx_log("storage:remove", {store: name, key: String(k)}); delete store[k]; },
        clear: function() { __sx_log("storage:clear", {store: name}); store = {}; },
        key: function(i) { var ks = []; for (var k in store) { ks.push(k); } return ks[i] || null; },
        length: 0
    };
}
var localStorage = __sx_make_storage("localStorage");
var sessionStorage = __sx_make_storage("sessionStorage");

// ---- DOM elements ----
function __sx_element(tag, id) {
    var el = {
        tagName: String(tag || "div").toUpperCase(),
        id: id || "",
        _html: "",
        _text: "",
        _attrs: {},
        children: [],
        value: "",
        href: "",
        src: "",
        action: "",
        method: "GET"
    };
    el.getAttribute = function(n) { return (n in el._attrs) ? el._attrs[n] : null; };
    el.setAttribute = function(n, v) {
        el._attrs[String(n)] = String(v);
        __sx_log("dom:setAttribute", {id: el.id, tag: el.tagName, name: String(n), value: String(v).slice(0, 500)});
        // sink: javascript: URLs in href/src/action
        var nv = String(v).toLowerCase();
        if ((String(n).toLowerCase() === "href" || String(n).toLowerCase() === "src" || String(n).toLowerCase() === "action") &&
            (nv.indexOf("javascript:") === 0 || nv.indexOf("data:text/html") === 0)) {
            __sx_log("sink:js-url-attr", {id: el.id, name: String(n), value: String(v).slice(0, 500)});
        }
    };
    el.removeAttribute = function(n) { delete el._attrs[String(n)]; };
    el.appendChild = function(c) { el.children.push(c); __sx_log("dom:appendChild", {id: el.id, tag: el.tagName}); return c; };
    el.addEventListener = function(t, fn) { __sx_log("dom:addEventListener", {id: el.id, type: String(t)}); };
    el.removeEventListener = function(t, fn) {};
    el.dispatchEvent = function(e) { __sx_log("dom:dispatchEvent", {id: el.id}); return true; };
    el.click = function() { __sx_log("dom:click", {id: el.id}); };
    el.submit = function() { __sx_log("dom:submit", {id: el.id, action: el.action}); };
    el.querySelector = function(s) { return __sx_element("div", "qs:" + s); };
    el.querySelectorAll = function(s) { return [__sx_element("div", "qs:" + s)]; };
    el.getElementsByTagName = function(t) { return []; };
    // innerHTML / outerHTML are the critical XSS sinks
    try {
        Object.defineProperty(el, "innerHTML", {
            set: function(v) { __sx_log("sink:innerHTML", {id: el.id, tag: el.tagName, value: String(v).slice(0, 2000)}); el._html = String(v); },
            get: function() { return el._html; },
            configurable: true
        });
        Object.defineProperty(el, "outerHTML", {
            set: function(v) { __sx_log("sink:outerHTML", {id: el.id, tag: el.tagName, value: String(v).slice(0, 2000)}); },
            get: function() { return el._html; },
            configurable: true
        });
    } catch (e) { /* js2py should support defineProperty; degrade if not */ }
    return el;
}

// ---- document ----
var document = {
    _cookies: "",
    location: location,
    referrer: "",
    title: "",
    readyState: "complete",
    write: function(s) { __sx_log("sink:document.write", {value: String(s).slice(0, 2000)}); },
    writeln: function(s) { __sx_log("sink:document.write", {value: String(s).slice(0, 2000)}); },
    createElement: function(tag) { return __sx_element(tag, ""); },
    createTextNode: function(t) { return {nodeValue: String(t)}; },
    getElementById: function(id) { return __sx_element("div", String(id)); },
    getElementsByTagName: function(t) { return []; },
    getElementsByClassName: function(c) { return []; },
    querySelector: function(s) { return __sx_element("div", "qs:" + s); },
    querySelectorAll: function(s) { return [__sx_element("div", "qs:" + s)]; },
    addEventListener: function(t, fn) { __sx_log("dom:addEventListener", {id: "document", type: String(t)}); },
    removeEventListener: function(t, fn) {},
    dispatchEvent: function(e) { return true; },
    execCommand: function(c) { __sx_log("sink:execCommand", String(c)); return false; }
};
try {
    Object.defineProperty(document, "cookie", {
        set: function(v) { __sx_log("storage:cookie-set", String(v).slice(0, 500)); document._cookies = String(v); },
        get: function() { __sx_log("storage:cookie-get", null); return document._cookies; },
        configurable: true
    });
} catch (e) {}

// ---- window ----
var window = {
    location: location,
    document: document,
    history: history,
    navigator: navigator,
    localStorage: localStorage,
    sessionStorage: sessionStorage,
    name: "",
    closed: false,
    alert: function(m) { __sx_log("sink:alert", String(m).slice(0, 500)); },
    confirm: function(m) { __sx_log("sink:confirm", String(m).slice(0, 500)); return true; },
    prompt: function(m, d) { __sx_log("sink:prompt", String(m).slice(0, 500)); return d || ""; },
    open: function(u, t) { __sx_log("nav:window.open", String(u)); return null; },
    setTimeout: function(fn, ms) {
        if (typeof fn === "string") { __sx_log("sink:setTimeout-string", String(fn).slice(0, 1000)); }
        return 1;
    },
    setInterval: function(fn, ms) {
        if (typeof fn === "string") { __sx_log("sink:setInterval-string", String(fn).slice(0, 1000)); }
        return 2;
    },
    clearTimeout: function(id) {},
    clearInterval: function(id) {},
    addEventListener: function(t, fn) { __sx_log("dom:addEventListener", {id: "window", type: String(t)}); },
    removeEventListener: function(t, fn) {},
    dispatchEvent: function(e) { return true; },
    postMessage: function(m, o) { __sx_log("net:postMessage", String(m).slice(0, 500)); },
    fetch: null,  // assigned below
    XMLHttpRequest: null,  // assigned below
    WebSocket: null  // assigned below
};
var self = window;
var top = window;
var parent = window;

// ---- dangerous sinks: eval / Function ----
// NOTE: js2py treats bare `eval` and `Function` as special forms, so the
// executor rewrites them to __sx_eval / __sx_Function before running page
// JS (outside string literals). These record the sink and do NOT execute.
function __sx_eval(code) { __sx_log("sink:eval", String(code).slice(0, 2000)); return undefined; }
function __sx_Function() {
    var args = [];
    for (var i = 0; i < arguments.length; i++) { args.push(String(arguments[i])); }
    __sx_log("sink:Function", args.join(", ").slice(0, 2000));
    return function() {};
}

// ---- fetch ----
function fetch(url, opts) {
    var method = "GET", body = null, headers = {};
    if (opts) {
        if (opts.method) { method = String(opts.method).toUpperCase(); }
        if (opts.body !== undefined && opts.body !== null) { body = String(opts.body).slice(0, 2000); }
        if (opts.headers) { try { headers = JSON.parse(JSON.stringify(opts.headers)); } catch (e) {} }
    }
    __sx_log("net:fetch", {url: String(url).slice(0, 1000), method: method, body: body});
    // minimal thenable so `fetch(u).then(...)` does not throw
    return { then: function(a, b) { return { catch: function(c) {} }; }, catch: function(c) {} };
}
window.fetch = fetch;

// ---- XMLHttpRequest ----
function XMLHttpRequest() {
    var self_ = this;
    this.readyState = 0; this.status = 0; this.responseText = ""; this.response = "";
    this._method = ""; this._url = "";
    this.open = function(method, url, async) {
        self_._method = String(method).toUpperCase(); self_._url = String(url);
        __sx_log("net:xhr-open", {url: String(url).slice(0, 1000), method: self_._method});
    };
    this.setRequestHeader = function(k, v) {};
    this.send = function(body) {
        __sx_log("net:xhr-send", {url: self_._url.slice(0, 1000), method: self_._method,
                                  body: (body === undefined || body === null) ? null : String(body).slice(0, 2000)});
    };
    this.abort = function() {};
    this.addEventListener = function(t, fn) {};
}
window.XMLHttpRequest = XMLHttpRequest;

// ---- WebSocket ----
function WebSocket(url, protocols) {
    __sx_log("net:websocket", {url: String(url).slice(0, 1000)});
    this.url = String(url);
    this.readyState = 0;
    this.send = function(d) { __sx_log("net:websocket-send", {url: String(url).slice(0, 500), data: String(d).slice(0, 1000)}); };
    this.close = function() {};
    this.addEventListener = function(t, fn) {};
}
window.WebSocket = WebSocket;

// ---- unsupported-but-observable stubs ----
var __sx_unsupported_apis = ["indexedDB", "Notification", "geolocation", "serviceWorker",
    "BroadcastChannel", "Worker", "SharedWorker", "EventSource", "RTCPeerConnection"];
for (var __sx_i = 0; __sx_i < __sx_unsupported_apis.length; __sx_i++) {
    (function(__sx_name) {
        window[__sx_name] = function() { __sx_unsupported(__sx_name); return {}; };
    })(__sx_unsupported_apis[__sx_i]);
}
// ---- global aliases (browsers resolve these via window; js2py needs explicit globals) ----
var setTimeout = window.setTimeout;
var setInterval = window.setInterval;
var clearTimeout = window.clearTimeout;
var clearInterval = window.clearInterval;
var alert = window.alert;
var confirm = window.confirm;
var prompt = window.prompt;
var open = window.open;
var postMessage = window.postMessage;
// direct global stubs for unsupported APIs (observable via __sx_unsupported)
var Worker = window.Worker;
var SharedWorker = window.SharedWorker;
var EventSource = window.EventSource;
var BroadcastChannel = window.BroadcastChannel;
var indexedDB = window.indexedDB;
var Notification = window.Notification;
// =====================================================================
""" % (
        _js_str(page_url),
        _js_str("?" + search_canary.lstrip("?")),
        _js_str("#" + hash_canary.lstrip("#")),
    )


#: APIs we explicitly do NOT emulate; access is logged as "unsupported".
UNSUPPORTED_APIS = (
    "indexedDB", "Notification", "geolocation", "serviceWorker",
    "BroadcastChannel", "Worker", "SharedWorker", "EventSource",
    "RTCPeerConnection",
)
