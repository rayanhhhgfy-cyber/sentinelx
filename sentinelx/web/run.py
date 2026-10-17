"""SentinelX web backend entrypoint."""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sentinelx.web.server:app", host="127.0.0.1", port=8000)
