# 🎙️ Realtime Voice Chat GPT Proxy

Ein hochperformanter Docker-basierter Proxy-Server, der als intelligente Brücke zwischen Frontend-Anwendungen und der OpenAI Realtime API fungiert. Das Besondere: Frontend-Functions können dynamisch als Tools registriert werden, die von der AI aufgerufen werden können.

## ✨ Features

- 🔊 **Bidirektionales Audio-Streaming** - Realtime Voice Input/Output
- 🔧 **Dynamic Function Registration** - Registriere JavaScript/TypeScript Functions als AI-Tools
- 🐳 **Docker-Ready** - Production-ready Container mit Docker Compose
- 🔄 **Auto-Reconnection** - Robuste Verbindungsverwaltung
- 🛡️ **Security-First** - JWT Auth, Rate Limiting, Input Validation
- 📊 **Monitoring** - Prometheus Metrics, Health Checks
- 🎯 **TypeScript** - Vollständige Type-Safety

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- OpenAI API Key mit Realtime API Zugang
- Node.js 20+ (für lokale Entwicklung)

### Installation

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/dockervoice.git
cd dockervoice
```

2. **Environment Setup**
```bash
cp .env.example .env
# Edit .env und füge deinen OpenAI API Key ein
```

3. **Start mit Docker**
```bash
docker-compose up -d
```

Der Proxy läuft nun auf `http://localhost:8080`

## 🔨 Verwendung

### Frontend Integration

```javascript
import { VoiceChatClient } from '@voice-proxy/sdk';

// Client initialisieren
const client = new VoiceChatClient({
  url: 'ws://localhost:8080/ws',
  token: 'your-auth-token'
});

// Function registrieren
client.registerFunction(
  'getWeather',
  async ({ location }) => {
    const response = await fetch(`/api/weather?location=${location}`);
    return response.json();
  },
  {
    description: 'Get current weather',
    parameters: {
      type: 'object',
      properties: {
        location: { type: 'string' }
      }
    }
  }
);

// Events abonnieren
client.on('transcription', (data) => {
  console.log('User:', data.text);
});

client.on('response', (data) => {
  console.log('AI:', data.text);
});

// Verbinden und starten
await client.connect();
await client.startListening();
```

### React Hook Example

```jsx
import { useVoiceChat } from '@voice-proxy/react';

function VoiceAssistant() {
  const {
    isListening,
    transcription,
    response,
    startListening,
    stopListening,
    registerFunction
  } = useVoiceChat({
    url: 'ws://localhost:8080/ws'
  });

  useEffect(() => {
    registerFunction('getTime', () => new Date().toISOString());
  }, []);

  return (
    <div>
      <button onClick={isListening ? stopListening : startListening}>
        {isListening ? '🔴 Stop' : '🎤 Start'}
      </button>
      {transcription && <p>You: {transcription}</p>}
      {response && <p>AI: {response}</p>}
    </div>
  );
}
```

## 📁 Projektstruktur

```
dockervoice/
├── docs/                    # Detaillierte Dokumentation
│   ├── 01-architecture.md  # System-Architektur
│   ├── 02-api-reference.md # API Dokumentation
│   ├── 03-function-registry.md
│   ├── 04-websocket-protocol.md
│   ├── 05-docker-deployment.md
│   └── 06-security.md
├── proxy/                   # Proxy Server (Node.js/TypeScript)
├── frontend-sdk/            # JavaScript/TypeScript SDK
├── examples/                # Beispiel-Implementierungen
└── docker-compose.yml       # Docker Orchestration
```

## 🔧 Konfiguration

### Environment Variables

| Variable | Beschreibung | Default |
|----------|--------------|---------|
| `OPENAI_API_KEY` | OpenAI API Schlüssel | Required |
| `PORT` | Proxy Server Port | 8080 |
| `REDIS_URL` | Redis Connection URL | redis://localhost:6379 |
| `JWT_SECRET` | JWT Secret für Auth | Required in Production |
| `MAX_SESSIONS` | Max. gleichzeitige Sessions | 1000 |
| `SESSION_TIMEOUT` | Session Timeout in ms | 3600000 |

## 🐳 Docker Deployment

### Production Deployment

```bash
# Build und Start
docker-compose up -d --build

# Scaling
docker-compose up -d --scale proxy=3

# Logs anzeigen
docker-compose logs -f proxy

# Health Check
curl http://localhost:8080/health
```

### Kubernetes Deployment

```bash
kubectl apply -f k8s/
```

## 🔒 Security

- **Authentication**: JWT Tokens oder API Keys
- **Rate Limiting**: Konfigurierbar pro Client
- **Input Validation**: JSON Schema Validation
- **Sandboxing**: Function Execution in isoliertem Context
- **Encryption**: TLS/SSL für Production

Details siehe [Security Documentation](docs/06-security.md)

## 📊 Monitoring

- **Health Endpoint**: `/health`
- **Metrics Endpoint**: `/metrics` (Prometheus Format)
- **Grafana Dashboards**: Vorkonfiguriert in `monitoring/`

## 🧪 Testing

```bash
# Unit Tests
npm test

# Integration Tests
npm run test:integration

# Load Testing
npm run test:load
```

## 🛠️ Development

### Lokale Entwicklung

```bash
# Dependencies installieren
cd proxy && npm install
cd ../frontend-sdk && npm install

# Proxy Server starten
cd proxy && npm run dev

# SDK entwickeln
cd frontend-sdk && npm run dev
```

### Mit Docker

```bash
docker-compose -f docker-compose.dev.yml up
```

## 📚 Dokumentation

Detaillierte Dokumentation findest du im `docs/` Verzeichnis:

- [System Architecture](docs/01-architecture.md)
- [API Reference](docs/02-api-reference.md)
- [Function Registry](docs/03-function-registry.md)
- [WebSocket Protocol](docs/04-websocket-protocol.md)
- [Docker Deployment](docs/05-docker-deployment.md)
- [Security Guide](docs/06-security.md)

## 🤝 Contributing

Contributions sind willkommen! Bitte erstelle einen Pull Request oder öffne ein Issue.

## 📄 License

MIT License - siehe [LICENSE](LICENSE) file

## 🆘 Support

Bei Fragen oder Problemen:
- Öffne ein [GitHub Issue](https://github.com/yourusername/dockervoice/issues)
- Schreibe an: support@example.com

## 🚧 Roadmap

- [ ] Multi-Language Support
- [ ] Voice Cloning
- [ ] Group Conversations
- [ ] Plugin System
- [ ] GraphQL API
- [ ] Analytics Dashboard

---

Built with ❤️ using OpenAI Realtime API