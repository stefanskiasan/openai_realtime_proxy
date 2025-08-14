# 📚 API Reference - Voice Chat GPT Proxy

## Base Configuration

### Environment Variables

```bash
# Required
OPENAI_API_KEY=sk-...           # OpenAI API Key
REDIS_URL=redis://localhost:6379 # Redis Connection URL

# Optional
PORT=8080                        # Proxy Server Port (default: 8080)
WS_PATH=/ws                      # WebSocket Path (default: /ws)
LOG_LEVEL=info                   # Logging Level (error|warn|info|debug)
MAX_SESSIONS=1000                # Maximum concurrent sessions
SESSION_TIMEOUT=3600000          # Session timeout in ms (default: 1 hour)
ENABLE_CORS=true                 # Enable CORS (default: true)
CORS_ORIGIN=*                    # CORS allowed origins
RATE_LIMIT_WINDOW=60000          # Rate limit window in ms
RATE_LIMIT_MAX_REQUESTS=100      # Max requests per window
```

## HTTP Endpoints

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600,
  "connections": {
    "redis": "connected",
    "openai": "ready"
  },
  "stats": {
    "activeSessions": 42,
    "totalFunctionCalls": 1337,
    "audioMinutesProcessed": 256.5
  }
}
```

### Session Information

```http
GET /api/session/:sessionId
Authorization: Bearer <token>
```

**Response:**
```json
{
  "sessionId": "sess_abc123",
  "status": "active",
  "created": "2024-01-15T10:00:00Z",
  "lastActivity": "2024-01-15T10:30:00Z",
  "functions": [
    {
      "name": "getWeather",
      "version": "1.0.0",
      "callCount": 5
    }
  ],
  "metrics": {
    "audioInSeconds": 120,
    "audioOutSeconds": 180,
    "functionCalls": 12,
    "errors": 0
  }
}
```

### List Active Sessions

```http
GET /api/sessions
Authorization: Bearer <admin-token>
```

**Query Parameters:**
- `limit` (number): Maximum results (default: 100)
- `offset` (number): Pagination offset (default: 0)
- `status` (string): Filter by status (active|inactive|all)

**Response:**
```json
{
  "sessions": [
    {
      "sessionId": "sess_abc123",
      "clientId": "client_xyz",
      "status": "active",
      "created": "2024-01-15T10:00:00Z"
    }
  ],
  "total": 42,
  "limit": 100,
  "offset": 0
}
```

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

// With authentication
const ws = new WebSocket('ws://localhost:8080/ws', {
  headers: {
    'Authorization': 'Bearer <token>'
  }
});
```

### Message Protocol

All WebSocket messages follow this structure:

```typescript
interface WebSocketMessage {
  type: string;
  id?: string;          // Optional message ID for request-response matching
  timestamp: number;    // Unix timestamp
  data: any;           // Message-specific data
}
```

## WebSocket Message Types

### Client → Proxy Messages

#### 1. Session Initialization

```json
{
  "type": "session.init",
  "id": "msg_123",
  "timestamp": 1705312800000,
  "data": {
    "clientId": "client_xyz",
    "config": {
      "model": "gpt-4-realtime",
      "voice": "alloy",
      "temperature": 0.7,
      "maxTokens": 4096,
      "language": "en-US"
    }
  }
}
```

**Response:**
```json
{
  "type": "session.created",
  "id": "msg_123",
  "timestamp": 1705312800100,
  "data": {
    "sessionId": "sess_abc123",
    "status": "ready"
  }
}
```

#### 2. Function Registration

```json
{
  "type": "function.register",
  "id": "msg_124",
  "timestamp": 1705312801000,
  "data": {
    "name": "getWeather",
    "description": "Get current weather for a location",
    "parameters": {
      "type": "object",
      "properties": {
        "location": {
          "type": "string",
          "description": "City name or coordinates"
        },
        "units": {
          "type": "string",
          "enum": ["celsius", "fahrenheit"],
          "default": "celsius"
        }
      },
      "required": ["location"]
    },
    "version": "1.0.0"
  }
}
```

**Response:**
```json
{
  "type": "function.registered",
  "id": "msg_124",
  "timestamp": 1705312801100,
  "data": {
    "name": "getWeather",
    "toolId": "tool_weather_123",
    "status": "active"
  }
}
```

#### 3. Function Update

```json
{
  "type": "function.update",
  "id": "msg_125",
  "timestamp": 1705312802000,
  "data": {
    "name": "getWeather",
    "updates": {
      "description": "Updated description",
      "parameters": { /* ... */ }
    }
  }
}
```

#### 4. Function Unregister

```json
{
  "type": "function.unregister",
  "id": "msg_126",
  "timestamp": 1705312803000,
  "data": {
    "name": "getWeather"
  }
}
```

#### 5. Audio Stream (Client → Proxy)

```json
{
  "type": "audio.stream",
  "timestamp": 1705312804000,
  "data": {
    "audio": "base64_encoded_pcm16_audio",
    "format": "pcm16",
    "sampleRate": 24000,
    "channels": 1
  }
}
```

#### 6. Audio Control

```json
{
  "type": "audio.control",
  "id": "msg_127",
  "timestamp": 1705312805000,
  "data": {
    "action": "stop" | "pause" | "resume" | "clear"
  }
}
```

#### 7. Conversation Control

```json
{
  "type": "conversation.interrupt",
  "timestamp": 1705312806000,
  "data": {
    "reason": "user_interrupt"
  }
}
```

### Proxy → Client Messages

#### 1. Function Call Request

```json
{
  "type": "function.call",
  "id": "call_789",
  "timestamp": 1705312810000,
  "data": {
    "name": "getWeather",
    "arguments": {
      "location": "Berlin",
      "units": "celsius"
    },
    "timeout": 5000
  }
}
```

**Expected Response:**
```json
{
  "type": "function.result",
  "id": "call_789",
  "timestamp": 1705312810500,
  "data": {
    "success": true,
    "result": {
      "temperature": 15,
      "condition": "partly_cloudy",
      "humidity": 65
    }
  }
}
```

**Or Error Response:**
```json
{
  "type": "function.result",
  "id": "call_789",
  "timestamp": 1705312810500,
  "data": {
    "success": false,
    "error": {
      "code": "FUNCTION_ERROR",
      "message": "Failed to fetch weather data"
    }
  }
}
```

#### 2. Audio Stream (Proxy → Client)

```json
{
  "type": "audio.stream",
  "timestamp": 1705312811000,
  "data": {
    "audio": "base64_encoded_pcm16_audio",
    "format": "pcm16",
    "sampleRate": 24000,
    "channels": 1,
    "sequenceNumber": 42
  }
}
```

#### 3. Transcription

```json
{
  "type": "transcription",
  "timestamp": 1705312812000,
  "data": {
    "text": "What's the weather like in Berlin?",
    "isFinal": true,
    "confidence": 0.95
  }
}
```

#### 4. AI Response

```json
{
  "type": "response.text",
  "timestamp": 1705312813000,
  "data": {
    "text": "Let me check the weather in Berlin for you.",
    "isComplete": false
  }
}
```

#### 5. Status Updates

```json
{
  "type": "status",
  "timestamp": 1705312814000,
  "data": {
    "state": "listening" | "thinking" | "speaking" | "idle",
    "details": "Processing your request..."
  }
}
```

#### 6. Error Messages

```json
{
  "type": "error",
  "timestamp": 1705312815000,
  "data": {
    "code": "OPENAI_ERROR",
    "message": "Failed to connect to OpenAI",
    "details": {
      "retry": true,
      "retryAfter": 1000
    }
  }
}
```

## Error Codes

| Code | Description | Retry |
|------|-------------|-------|
| `AUTH_FAILED` | Authentication failed | No |
| `SESSION_EXPIRED` | Session has expired | Yes |
| `RATE_LIMIT` | Rate limit exceeded | Yes |
| `FUNCTION_NOT_FOUND` | Function not registered | No |
| `FUNCTION_TIMEOUT` | Function execution timeout | Yes |
| `FUNCTION_ERROR` | Function execution error | Maybe |
| `OPENAI_ERROR` | OpenAI API error | Yes |
| `AUDIO_FORMAT_ERROR` | Invalid audio format | No |
| `INVALID_MESSAGE` | Invalid message format | No |
| `SERVER_ERROR` | Internal server error | Yes |
| `REDIS_ERROR` | Redis connection error | Yes |

## Rate Limiting

Rate limiting is applied per client ID:

- **Default Limits:**
  - 100 requests per minute
  - 1000 function calls per hour
  - 60 minutes of audio per hour

- **Headers:**
  ```
  X-RateLimit-Limit: 100
  X-RateLimit-Remaining: 42
  X-RateLimit-Reset: 1705312900000
  ```

## WebSocket Close Codes

| Code | Meaning |
|------|---------|
| 1000 | Normal closure |
| 1001 | Going away |
| 1002 | Protocol error |
| 1003 | Unsupported data |
| 1008 | Policy violation (auth/rate limit) |
| 1011 | Server error |
| 4000 | Session expired |
| 4001 | Authentication required |
| 4002 | Rate limit exceeded |
| 4003 | Invalid message format |

## SDK Usage Examples

### JavaScript/TypeScript

```typescript
import { VoiceChatClient } from '@voice-proxy/sdk';

// Initialize client
const client = new VoiceChatClient({
  url: 'ws://localhost:8080/ws',
  token: 'your-auth-token',
  debug: true
});

// Register a function
client.registerFunction(
  'getWeather',
  async (args: { location: string }) => {
    const response = await fetch(`/api/weather?location=${args.location}`);
    return response.json();
  },
  {
    description: 'Get weather information',
    parameters: {
      type: 'object',
      properties: {
        location: { type: 'string' }
      },
      required: ['location']
    }
  }
);

// Handle events
client.on('status', (status) => {
  console.log('Status:', status.state);
});

client.on('transcription', (data) => {
  console.log('User said:', data.text);
});

client.on('response.text', (data) => {
  console.log('AI says:', data.text);
});

// Start conversation
await client.connect();
await client.startListening();
```

### React Hook

```typescript
import { useVoiceChat } from '@voice-proxy/react';

function VoiceAssistant() {
  const {
    isConnected,
    isListening,
    isSpeaking,
    transcription,
    response,
    startListening,
    stopListening,
    registerFunction
  } = useVoiceChat({
    url: 'ws://localhost:8080/ws',
    token: 'your-auth-token'
  });

  useEffect(() => {
    registerFunction('getTime', () => new Date().toISOString());
  }, []);

  return (
    <div>
      <button onClick={isListening ? stopListening : startListening}>
        {isListening ? 'Stop' : 'Start'}
      </button>
      {transcription && <p>You: {transcription}</p>}
      {response && <p>AI: {response}</p>}
    </div>
  );
}
```

## Best Practices

1. **Connection Management**
   - Implement exponential backoff for reconnections
   - Handle connection drops gracefully
   - Clean up resources on disconnect

2. **Function Registration**
   - Register functions early in session lifecycle
   - Use versioning for function updates
   - Implement proper error handling in functions

3. **Audio Streaming**
   - Use appropriate buffer sizes (recommend 100-200ms)
   - Handle audio interruptions smoothly
   - Implement echo cancellation on client side

4. **Error Handling**
   - Always handle error messages
   - Implement retry logic where appropriate
   - Log errors for debugging

5. **Performance**
   - Batch function registrations when possible
   - Use compression for large payloads
   - Monitor latency and adjust timeouts

## Testing

### WebSocket Testing with wscat

```bash
# Install wscat
npm install -g wscat

# Connect to proxy
wscat -c ws://localhost:8080/ws

# Send initialization message
{"type":"session.init","data":{"clientId":"test"}}

# Register a function
{"type":"function.register","data":{"name":"test","parameters":{}}}
```

### Load Testing

```bash
# Using artillery.io
npm install -g artillery

# Run load test
artillery run tests/load-test.yml
```

Example `load-test.yml`:
```yaml
config:
  target: "ws://localhost:8080"
  phases:
    - duration: 60
      arrivalRate: 10
  ws:
    path: "/ws"
scenarios:
  - name: "Voice Chat Session"
    engine: ws
    flow:
      - send: '{"type":"session.init","data":{"clientId":"test"}}'
      - think: 1
      - send: '{"type":"function.register","data":{"name":"test"}}'
      - think: 5
```