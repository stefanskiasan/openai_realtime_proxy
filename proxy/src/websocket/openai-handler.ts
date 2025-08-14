import { EventEmitter } from 'events';
import WebSocket from 'ws';
import { Logger } from '../utils/logger';
import { Config } from '../config/config';

interface OpenAIConfig {
  model?: string;
  voice?: string;
  temperature?: number;
  maxTokens?: number;
  language?: string;
  instructions?: string;
}

export class OpenAIHandler extends EventEmitter {
  private ws: WebSocket | null = null;
  private sessionId: string;
  private openAISessionId: string | null = null;
  private logger: Logger;
  private config: Config;
  private isConnected: boolean = false;
  private audioBuffer: Buffer[] = [];
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private tools: any[] = [];

  constructor(sessionId: string) {
    super();
    this.sessionId = sessionId;
    this.logger = new Logger(`OpenAIHandler:${sessionId}`);
    this.config = Config.getInstance();
  }

  public async connect(userConfig: OpenAIConfig): Promise<void> {
    const apiKey = this.config.get('OPENAI_API_KEY');
    
    if (!apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    const url = 'wss://api.openai.com/v1/realtime?model=gpt-4o-realtime-preview-2024-12-17';
    
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(url, {
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'OpenAI-Beta': 'realtime=v1'
          }
        });

        this.ws.on('open', () => {
          this.logger.info('Connected to OpenAI Realtime API');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          
          // Send session configuration
          this.sendSessionUpdate(userConfig);
          
          resolve();
        });

        this.ws.on('message', (data: any) => {
          this.handleMessage(data);
        });

        this.ws.on('error', (error) => {
          this.logger.error('OpenAI WebSocket error:', error);
          this.emit('error', error);
          
          if (!this.isConnected) {
            reject(error);
          }
        });

        this.ws.on('close', (code, reason) => {
          this.logger.info('OpenAI connection closed', { code, reason: reason?.toString() });
          this.isConnected = false;
          
          if (code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.attemptReconnect(userConfig);
          }
        });

      } catch (error) {
        this.logger.error('Failed to connect to OpenAI:', error);
        reject(error);
      }
    });
  }

  private sendSessionUpdate(config: OpenAIConfig): void {
    const sessionConfig = {
      type: 'session.update',
      session: {
        modalities: ['text', 'audio'],
        instructions: config.instructions || 'You are a helpful assistant.',
        voice: config.voice || 'alloy',
        input_audio_format: 'pcm16',
        output_audio_format: 'pcm16',
        input_audio_transcription: {
          model: 'whisper-1'
        },
        turn_detection: {
          type: 'server_vad',
          threshold: 0.5,
          prefix_padding_ms: 300,
          silence_duration_ms: 500
        },
        tools: this.tools,
        temperature: config.temperature || 0.7,
        max_response_output_tokens: config.maxTokens || 4096
      }
    };

    this.send(sessionConfig);
  }

  private handleMessage(data: any): void {
    try {
      const message = JSON.parse(data.toString());
      
      this.logger.debug('OpenAI message received:', { type: message.type });

      switch (message.type) {
        case 'session.created':
          this.handleSessionCreated(message);
          break;

        case 'session.updated':
          this.logger.info('Session updated');
          break;

        case 'conversation.item.created':
          this.handleConversationItem(message);
          break;

        case 'response.audio.delta':
          this.handleAudioDelta(message);
          break;

        case 'response.audio.done':
          this.handleAudioDone(message);
          break;

        case 'response.text.delta':
          this.handleTextDelta(message);
          break;

        case 'response.text.done':
          this.handleTextDone(message);
          break;

        case 'response.function_call_arguments.delta':
          this.handleFunctionCallDelta(message);
          break;

        case 'response.function_call_arguments.done':
          this.handleFunctionCallDone(message);
          break;

        case 'input_audio_buffer.speech_started':
          this.emit('speech.started');
          break;

        case 'input_audio_buffer.speech_stopped':
          this.emit('speech.stopped');
          break;

        case 'conversation.item.input_audio_transcription.completed':
          this.handleTranscription(message);
          break;

        case 'response.done':
          this.handleResponseDone(message);
          break;

        case 'error':
          this.handleError(message);
          break;

        default:
          this.logger.debug('Unhandled message type:', message.type);
      }

    } catch (error) {
      this.logger.error('Failed to handle OpenAI message:', error);
    }
  }

  private handleSessionCreated(message: any): void {
    this.openAISessionId = message.session.id;
    this.logger.info('OpenAI session created:', this.openAISessionId);
    this.emit('session.created', message.session);
  }

  private handleConversationItem(message: any): void {
    const item = message.item;
    
    if (item.type === 'message' && item.role === 'assistant') {
      this.emit('response.started', {
        id: item.id,
        role: item.role
      });
    }
  }

  private handleAudioDelta(message: any): void {
    if (message.delta) {
      const audioData = Buffer.from(message.delta, 'base64');
      this.audioBuffer.push(audioData);
      
      // Stream audio chunks immediately for low latency
      this.emit('audio', audioData);
    }
  }

  private handleAudioDone(message: any): void {
    if (this.audioBuffer.length > 0) {
      const completeAudio = Buffer.concat(this.audioBuffer);
      this.audioBuffer = [];
      this.emit('audio.complete', completeAudio);
    }
  }

  private handleTextDelta(message: any): void {
    if (message.delta) {
      this.emit('response', {
        text: message.delta,
        isComplete: false
      });
    }
  }

  private handleTextDone(message: any): void {
    this.emit('response', {
      text: message.text,
      isComplete: true
    });
  }

  private currentFunctionCall: any = null;

  private handleFunctionCallDelta(message: any): void {
    if (!this.currentFunctionCall) {
      this.currentFunctionCall = {
        id: message.item_id,
        function: {
          name: message.name,
          arguments: ''
        }
      };
    }
    
    if (message.arguments) {
      this.currentFunctionCall.function.arguments += message.arguments;
    }
  }

  private handleFunctionCallDone(message: any): void {
    if (this.currentFunctionCall) {
      this.emit('function.call', this.currentFunctionCall);
      this.currentFunctionCall = null;
    }
  }

  private handleTranscription(message: any): void {
    this.emit('transcription', {
      text: message.transcript,
      isFinal: true,
      confidence: 1.0,
      language: 'en-US',
      speaker: 'user'
    });
  }

  private handleResponseDone(message: any): void {
    this.emit('response.done', {
      id: message.response.id,
      status: message.response.status,
      usage: message.response.usage
    });
  }

  private handleError(message: any): void {
    this.logger.error('OpenAI error:', message.error);
    this.emit('error', message.error);
  }

  public async sendAudio(audioData: Buffer): Promise<void> {
    if (!this.isConnected || !this.ws) {
      throw new Error('Not connected to OpenAI');
    }

    // Convert audio to base64
    const base64Audio = audioData.toString('base64');
    
    this.send({
      type: 'input_audio_buffer.append',
      audio: base64Audio
    });
  }

  public async sendFunctionResult(callId: string, result: any): Promise<void> {
    if (!this.isConnected || !this.ws) {
      throw new Error('Not connected to OpenAI');
    }

    this.send({
      type: 'conversation.item.create',
      item: {
        type: 'function_call_output',
        call_id: callId,
        output: JSON.stringify(result)
      }
    });

    // Trigger response generation
    this.send({
      type: 'response.create'
    });
  }

  public async updateTools(tools: any[]): Promise<void> {
    this.tools = tools;
    
    if (this.isConnected && this.ws) {
      this.send({
        type: 'session.update',
        session: {
          tools: this.tools
        }
      });
    }
  }

  public async interrupt(reason: string): Promise<void> {
    if (!this.isConnected || !this.ws) {
      throw new Error('Not connected to OpenAI');
    }

    this.send({
      type: 'response.cancel'
    });

    // Clear audio buffer
    this.audioBuffer = [];
    
    this.logger.info('Conversation interrupted:', reason);
  }

  public async stopAudio(): Promise<void> {
    this.send({
      type: 'response.cancel'
    });
  }

  public async pauseAudio(): Promise<void> {
    // OpenAI doesn't support pause, simulate with cancel
    this.send({
      type: 'response.cancel'
    });
  }

  public async resumeAudio(): Promise<void> {
    // Trigger new response
    this.send({
      type: 'response.create'
    });
  }

  public async clearAudioBuffer(): Promise<void> {
    if (!this.isConnected || !this.ws) {
      throw new Error('Not connected to OpenAI');
    }

    this.send({
      type: 'input_audio_buffer.clear'
    });
    
    this.audioBuffer = [];
  }

  private send(data: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
      this.logger.debug('Sent to OpenAI:', { type: data.type });
    } else {
      this.logger.warn('Cannot send message, WebSocket not open');
    }
  }

  private async attemptReconnect(config: OpenAIConfig): Promise<void> {
    this.reconnectAttempts++;
    
    const delay = Math.min(
      1000 * Math.pow(2, this.reconnectAttempts - 1),
      30000
    );

    this.logger.info(`Attempting reconnect in ${delay}ms...`);

    setTimeout(async () => {
      try {
        await this.connect(config);
      } catch (error) {
        this.logger.error('Reconnect failed:', error);
      }
    }, delay);
  }

  public async reconnect(openAISessionId: string): Promise<void> {
    // OpenAI doesn't support session resumption directly
    // We'll need to recreate the session with the same configuration
    this.openAISessionId = openAISessionId;
    
    // Reconnect with stored configuration
    await this.connect({});
  }

  public async disconnect(): Promise<void> {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }
    
    this.isConnected = false;
    this.audioBuffer = [];
    this.removeAllListeners();
  }

  public isActive(): boolean {
    return this.isConnected;
  }

  public getSessionId(): string | null {
    return this.openAISessionId;
  }
}