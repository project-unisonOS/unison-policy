from fastapi import FastAPI
from fastapi import Body
import uvicorn

app = FastAPI(title="unison-policy")

@app.get("/health")
def health():
    return {"status": "ok", "service": "unison-policy"}

@app.get("/ready")
def ready():
    # Future: check audit log backend / key store
    return {"ready": True}

# Placeholder evaluate endpoint
# In the future orchestrator will call this before executing any high-risk capability.
@app.post("/evaluate")
def evaluate(
    capability_id: str = Body(..., embed=True),
    context: dict = Body(default_factory=dict, embed=True),
):
    # Static stub. Always "allow" for now.
    decision = {
        "allowed": True,
        "require_confirmation": False,
        "reason": "stub-allow",
    }
    return {
        "capability_id": capability_id,
        "decision": decision,
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8083)
