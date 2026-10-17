"""SentinelX jsenv: pure-Python JavaScript execution + analysis.

No Playwright, no headless browser, no compiled dependencies — works on
Termux. Provides:

- jsinterp: minimal JS subset interpreter with taint tracking
- mock: virtual browser environment (window/document/location/fetch/...)
- executor: high-level execute_js() API returning api_calls, dom_writes, etc.
- static: fast regex-based JS analysis (no execution)
"""
