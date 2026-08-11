"""Minimal agent-side integration. Run while AgentInterdict is listening on localhost:43847."""
import httpx

BASE = "http://127.0.0.1:43847"

def persist_memory(content, source_type="tool", source_uri=None):
    return httpx.post(f"{BASE}/api/v1/memories", json={
        "content": content, "source_type": source_type, "source_uri": source_uri,
        "namespace": "my-agent", "created_by": "example-agent"
    }).raise_for_status().json()

def recall(query):
    result = httpx.post(f"{BASE}/api/v1/search", json={"query": query, "namespace": "my-agent"}).raise_for_status().json()
    return result["items"]

if __name__ == "__main__":
    print(persist_memory("The customer prefers PDF invoices.", "human"))
    print(recall("invoice preference"))
