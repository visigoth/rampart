# ai/gemini — Google Gemini API (Generative Language) + AI Studio.

network {
  domain "generativelanguage.googleapis.com" {
    allow "POST" {
      paths = ["/v1/**", "/v1beta/**"]
    }
    allow "GET" {
      paths = ["/v1/**", "/v1beta/**"]
    }
  }
  domain "aistudio.google.com" {
    allow "GET" {
      paths = ["/**"]
    }
  }
}
