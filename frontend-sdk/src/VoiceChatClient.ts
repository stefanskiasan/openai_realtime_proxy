import { EventEmitter } from 'events';
import { FunctionRegistry } from './FunctionRegistry';
import { AudioManager } from './AudioManager';
import { 
  VoiceChatConfig, 
  WebSocketMessage, 
  ConnectionState,
  FunctionCall,
  FunctionResult
} from './types';

export class VoiceChatClient extends EventEmitter {
  private config: VoiceChatConfig;
  private ws: WebSocket | null = null;
  private connectionState: ConnectionState = 'disconnected';
  private sessionId: string | null = null;
  private functionRegistry: FunctionRegistry;
  private audioManager: AudioManager;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private messageQueue: WebSocketMessage[] = [];
  private pendingCalls: Map<string, (result: any) => void> = new Map();

  constructor(config: VoiceChatConfig) {
    super();
    this.config = config;
    this.functionRegistry = new FunctionRegistry();
    this.audioManager = new AudioManager(config.audioConfig);
    
    this.setupAudioHandlers();
  }

  private setupAudioHandlers(): void {
    this.audioManager.on('audio', (audioData: ArrayBuffer) => {
      this.sendAudioStream(audioData);
    });

    this.audioManager.on('error', (error: Error) => {
      this.emit('error', error);
    });
  }

  public async connect(): Promise<void> {
    if (this.connectionState !== 'disconnected') {
      throw new Error('Already connected or connecting');
    }

    this.connectionState = 'connecting';
    this.emit('connecting');

    return new Promise((resolve, reject) => {
      try {
        const url = new URL(this.config.url);
        
        // Add authentication to URL if provided
        if (this.config.token) {
          url.searchParams.set('token', this.config.token);
        }

        this.ws = new WebSocket(url.toString());
        
        this.ws.onopen = () => {
          this.connectionState = 'connected';
          this.reconnectAttempts = 0;
          this.emit('connected');
          this.flushMessageQueue();
          this.startHeartbeat();
          this.initializeSession();
          resolve();
        };

        this.ws.onmessage = (event) => {
          this.handleMessage(event.data);
        };

        this.ws.onerror = (error) => {
          this.emit('error', error);
          if (this.connectionState === 'connecting') {
            reject(error);
          }
        };

        this.ws.onclose = (event) => {
          this.connectionState = 'disconnected';
          this.stopHeartbeat();
          this.emit('disconnected', { code: event.code, reason: event.reason });
          
          if (event.code !== 1000 && this.config.autoReconnect !== false) {
            this.attemptReconnect();
          }
        };
      } catch (error) {
        this.connectionState = 'disconnected';
        reject(error);
      }
    });
  }

  private initializeSession(): void {
    this.send('session.init', {
      config: {
        model: this.config.model || 'gpt-4-realtime',
        voice: this.config.voice || 'alloy',
        temperature: this.config.temperature || 0.7,
        language: this.config.language || 'en-US',
        audioConfig: this.config.audioConfig
      }
    });
  }

  private handleMessage(data: string | ArrayBuffer): void {
    try {
      if (typeof data === 'string') {
        const message: WebSocketMessage = JSON.parse(data);
        this.processMessage(message);
      } else {
        // Handle binary audio data
        this.handleBinaryAudio(data);
      }
    } catch (error) {
      this.emit('error', new Error(`Failed to parse message: ${error}`));
    }
  }

  private processMessage(message: WebSocketMessage): void {
    if (this.config.debug) {
      console.log('Received message:', message);
    }

    switch (message.type) {
      case 'system.welcome':
        this.sessionId = message.data.sessionId;
        this.emit('ready', message.data);
        break;

      case 'session.created':
        this.sessionId = message.data.sessionId;
        this.emit('session.created', message.data);
        break;

      case 'function.call':
        this.handleFunctionCall(message);
        break;

      case 'audio.stream':
        this.audioManager.playAudio(message.data.audio);
        break;

      case 'conversation.transcription':
        this.emit('transcription', message.data);
        break;

      case 'conversation.response':
        this.emit('response', message.data);
        break;

      case 'status.processing':
        this.emit('status', message.data);
        break;

      case 'error':
        this.emit('error', new Error(message.data.message));
        break;

      case 'system.ping':
        this.send('system.pong', { sequence: message.data.sequence });
        break;

      default:
        this.emit(message.type, message.data);
    }
  }

  private async handleFunctionCall(message: WebSocketMessage): Promise<void> {
    const call: FunctionCall = message.data;
    
    try {
      const result = await this.functionRegistry.execute(call.name, call.arguments);
      
      this.send('function.result', {
        callId: call.callId || message.id,
        success: true,
        result
      });
    } catch (error: any) {
      this.send('function.result', {
        callId: call.callId || message.id,
        success: false,
        error: {
          code: 'FUNCTION_ERROR',
          message: error.message || 'Function execution failed'
        }
      });
    }
  }

  private handleBinaryAudio(data: ArrayBuffer): void {
    // Parse binary audio frame
    const view = new DataView(data);
    const frameType = view.getUint8(0);
    
    if (frameType === 0x01) {
      // Audio data frame
      const audioData = data.slice(7); // Skip header
      this.audioManager.playAudio(audioData);
    }
  }

  public registerFunction(
    name: string,
    handler: Function,
    schema?: any
  ): void {
    this.functionRegistry.register(name, handler, schema);
    
    if (this.connectionState === 'connected') {
      this.send('function.register', {
        name,
        description: schema?.description,
        parameters: schema?.parameters
      });
    }
  }

  public unregisterFunction(name: string): void {
    this.functionRegistry.unregister(name);
    
    if (this.connectionState === 'connected') {
      this.send('function.unregister', { name });
    }
  }

  public async startListening(): Promise<void> {
    await this.audioManager.startRecording();
    this.emit('listening');
  }

  public stopListening(): void {
    this.audioManager.stopRecording();
    this.emit('stopped-listening');
  }

  public send(type: string, data: any, options: any = {}): void {
    const message: WebSocketMessage = {
      type,
      timestamp: Date.now(),
      data,
      ...options
    };

    if (this.config.debug) {
      console.log('Sending message:', message);
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      this.messageQueue.push(message);
    }
  }

  private sendAudioStream(audioData: ArrayBuffer): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      // Convert to base64 for JSON transport
      const base64 = btoa(String.fromCharCode(...new Uint8Array(audioData)));
      
      this.send('audio.stream', {
        audio: base64,
        format: 'pcm16',
        sampleRate: 24000,
        channels: 1
      });
    }
  }

  private flushMessageQueue(): void {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (message && this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify(message));
      }
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.send('system.ping', { 
          sequence: Date.now() 
        });
      }
    }, 30000);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.emit('reconnect-failed');
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
      30000
    );

    this.emit('reconnecting', {
      attempt: this.reconnectAttempts,
      delay
    });

    setTimeout(() => {
      this.connect().catch(() => {
        // Error handled in connect method
      });
    }, delay);
  }

  public disconnect(): void {
    this.connectionState = 'disconnected';
    this.stopHeartbeat();
    
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    
    this.audioManager.cleanup();
  }

  public getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  public getSessionId(): string | null {
    return this.sessionId;
  }

  public isConnected(): boolean {
    return this.connectionState === 'connected';
  }
}