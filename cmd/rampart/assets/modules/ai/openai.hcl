# ai/openai — OpenAI API (Chat Completions, Responses, Embeddings).

network {
  domain "api.openai.com" {
    allow "POST" {
      paths = ["/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/v1/**"]
    }
    allow "GET" {
      paths = ["/v1/**"]
    }
  }
}
