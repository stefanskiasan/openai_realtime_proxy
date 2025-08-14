import { WebSocket } from 'ws';
import { EventEmitter } from 'events';
import { Logger } from '../utils/logger';
import { RedisClient } from '../utils/redis-client';
import { OpenAIHandler } from './openai-handler';
import { SessionManager } from '../session/session-manager';
import { FunctionRegistry } from '../registry/function-registry';
import { MessageRouter } from './message-router';
import { WebSocketMessage } from '../types';
import { v4 as uuidv4 } from 'uuid';

export class ClientHandler extends EventEmitter {
  private ws: WebSocket;
  private clientId: string;
  private clientIp: string;
  private sessionId: string | null = null;
  private logger: Logger;
  private redis: RedisClient;
  private openAIHandler: OpenAIHandler | null = null;
  private sessionManager: SessionManager;
  private functionRegistry: FunctionRegistry;
  private messageRouter: MessageRouter;
  private isAuthenticated: boolean = false;
  private lastActivity: Date;

  constructor(ws: WebSocket, clientId: string, clientIp: string) {
    super();
    this.ws = ws;
    this.clientId = clientId;
    this.clientIp = clientIp;
    this.logger = new Logger(`ClientHandler:${clientId}`);
    this.redis = RedisClient.getInstance();
    this.sessionManager = SessionManager.getInstance();
    this.functionRegistry = new FunctionRegistry();
    this.messageRouter = new MessageRouter(this);
    this.lastActivity = new Date();

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.ws.on('message', async (data: any) => {
      try {
        this.lastActivity = new Date();
        await this.handleMessage(data);
      } catch (error) {
        this.logger.error('Error handling message:', error);
        this.sendError('MESSAGE_ERROR', 'Failed to process message');
      }
    });

    this.ws.on('error', (error) => {
      this.logger.error('WebSocket error:', error);
    });

    this.ws.on('close', async () => {
      await this.cleanup();
    });
  }

  private async handleMessage(data: any): Promise<void> {
    try {
      let message: WebSocketMessage;

      if (typeof data === 'string') {
        message = JSON.parse(data);
      } else if (Buffer.isBuffer(data)) {
        // Handle binary audio data
        await this.handleBinaryAudio(data);
        return;
      } else {
        throw new Error('Invalid message format');
      }

      // Validate message structure
      if (!message.type || !message.timestamp) {
        throw new Error('Invalid message structure');
      }

      // Log message for debugging
      this.logger.debug('Received message:', { 
        type: message.type, 
        id: message.id 
      });

      // Route message to appropriate handler
      await this.messageRouter.route(message);

    } catch (error) {
      this.logger.error('Failed to handle message:', error);
      this.sendError('INVALID_MESSAGE', 'Invalid message format');
    }
  }

  private async handleBinaryAudio(data: Buffer): Promise<void> {
    if (!this.sessionId || !this.openAIHandler) {
      this.sendError('NO_SESSION', 'No active session');
      return;
    }

    // Forward audio to OpenAI
    await this.openAIHandler.sendAudio(data);
    
    // Update metrics
    await this.redis.incrementMetric('audio_chunks');
  }

  public async handleSessionInit(config: any): Promise<void> {
    try {
      // Create new session
      this.sessionId = uuidv4();
      const session = await this.sessionManager.createSession(this.sessionId, {
        clientId: this.clientId,
        clientIp: this.clientIp,
        config
      });

      // Initialize OpenAI connection
      this.openAIHandler = new OpenAIHandler(this.sessionId);
      await this.openAIHandler.connect(config);

      // Setup OpenAI event handlers
      this.setupOpenAIHandlers();

      // Send session created confirmation
      this.sendMessage({
        type: 'session.created',
        timestamp: Date.now(),
        data: {
          sessionId: this.sessionId,
          status: 'ready'
        }
      });

      this.logger.info('Session initialized:', this.sessionId);

    } catch (error) {
      this.logger.error('Failed to initialize session:', error);
      this.sendError('SESSION_INIT_FAILED', 'Failed to initialize session');
    }
  }

  public async handleSessionResume(sessionId: string): Promise<void> {
    try {
      const session = await this.sessionManager.getSession(sessionId);
      
      if (!session) {
        throw new Error('Session not found');
      }

      // Verify ownership
      if (session.clientId !== this.clientId) {
        throw new Error('Session ownership mismatch');
      }

      this.sessionId = sessionId;
      
      // Reinitialize OpenAI connection
      this.openAIHandler = new OpenAIHandler(sessionId);
      await this.openAIHandler.reconnect(session.openAISessionId);

      this.setupOpenAIHandlers();

      // Restore function registry
      const functions = await this.functionRegistry.getFunctions(sessionId);
      for (const func of functions) {
        await this.openAIHandler.updateTools([func]);
      }

      this.sendMessage({
        type: 'session.resumed',
        timestamp: Date.now(),
        data: {
          sessionId,
          status: 'ready'
        }
      });

      this.logger.info('Session resumed:', sessionId);

    } catch (error) {
      this.logger.error('Failed to resume session:', error);
      this.sendError('SESSION_RESUME_FAILED', 'Failed to resume session');
    }
  }

  private setupOpenAIHandlers(): void {
    if (!this.openAIHandler) return;

    // Handle audio from OpenAI
    this.openAIHandler.on('audio', (audioData: Buffer) => {
      this.sendAudioStream(audioData);
    });

    // Handle transcriptions
    this.openAIHandler.on('transcription', (data: any) => {
      this.sendMessage({
        type: 'conversation.transcription',
        timestamp: Date.now(),
        data
      });
    });

    // Handle AI responses
    this.openAIHandler.on('response', (data: any) => {
      this.sendMessage({
        type: 'conversation.response',
        timestamp: Date.now(),
        data
      });
    });

    // Handle function calls
    this.openAIHandler.on('function.call', async (call: any) => {
      await this.handleFunctionCall(call);
    });

    // Handle status updates
    this.openAIHandler.on('status', (status: any) => {
      this.sendMessage({
        type: 'status.processing',
        timestamp: Date.now(),
        data: status
      });
    });

    // Handle errors
    this.openAIHandler.on('error', (error: any) => {
      this.logger.error('OpenAI error:', error);
      this.sendError('OPENAI_ERROR', error.message);
    });
  }

  public async handleFunctionRegister(data: any): Promise<void> {
    if (!this.sessionId) {
      this.sendError('NO_SESSION', 'No active session');
      return;
    }

    try {
      // Register function in registry
      await this.functionRegistry.register(this.sessionId, data.name, data);

      // Update OpenAI tools
      if (this.openAIHandler) {
        const tool = this.functionRegistry.convertToTool(data);
        await this.openAIHandler.updateTools([tool]);
      }

      this.sendMessage({
        type: 'function.registered',
        timestamp: Date.now(),
        data: {
          name: data.name,
          status: 'active'
        }
      });

      this.logger.info('Function registered:', data.name);

    } catch (error) {
      this.logger.error('Failed to register function:', error);
      this.sendError('FUNCTION_REGISTER_FAILED', 'Failed to register function');
    }
  }

  public async handleFunctionUnregister(data: any): Promise<void> {
    if (!this.sessionId) {
      this.sendError('NO_SESSION', 'No active session');
      return;
    }

    try {
      await this.functionRegistry.unregister(this.sessionId, data.name);

      // Update OpenAI tools
      if (this.openAIHandler) {
        const remainingFunctions = await this.functionRegistry.getFunctions(this.sessionId);
        const tools = remainingFunctions.map(f => this.functionRegistry.convertToTool(f));
        await this.openAIHandler.updateTools(tools);
      }

      this.sendMessage({
        type: 'function.unregistered',
        timestamp: Date.now(),
        data: {
          name: data.name
        }
      });

      this.logger.info('Function unregistered:', data.name);

    } catch (error) {
      this.logger.error('Failed to unregister function:', error);
      this.sendError('FUNCTION_UNREGISTER_FAILED', 'Failed to unregister function');
    }
  }

  private async handleFunctionCall(call: any): Promise<void> {
    const callId = call.id || uuidv4();

    try {
      // Send function call request to client
      this.sendMessage({
        type: 'function.call',
        id: callId,
        timestamp: Date.now(),
        data: {
          callId: call.id,
          name: call.function.name,
          arguments: JSON.parse(call.function.arguments),
          timeout: 10000
        }
      });

      // Wait for response with timeout
      const result = await this.waitForFunctionResult(callId, 10000);

      // Send result back to OpenAI
      if (this.openAIHandler) {
        await this.openAIHandler.sendFunctionResult(call.id, result);
      }

    } catch (error) {
      this.logger.error('Function call failed:', error);
      
      // Send error to OpenAI
      if (this.openAIHandler) {
        await this.openAIHandler.sendFunctionResult(call.id, {
          error: error.message || 'Function execution failed'
        });
      }
    }
  }

  private waitForFunctionResult(callId: string, timeout: number): Promise<any> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        this.removeAllListeners(`function.result.${callId}`);
        reject(new Error('Function call timeout'));
      }, timeout);

      this.once(`function.result.${callId}`, (result: any) => {
        clearTimeout(timeoutId);
        
        if (result.success) {
          resolve(result.result);
        } else {
          reject(new Error(result.error?.message || 'Function execution failed'));
        }
      });
    });
  }

  public handleFunctionResult(message: WebSocketMessage): void {
    const callId = message.id || message.data.callId;
    if (callId) {
      this.emit(`function.result.${callId}`, message.data);
    }
  }

  public async handleAudioControl(data: any): Promise<void> {
    if (!this.openAIHandler) {
      this.sendError('NO_SESSION', 'No active session');
      return;
    }

    try {
      switch (data.action) {
        case 'stop':
          await this.openAIHandler.stopAudio();
          break;
        case 'pause':
          await this.openAIHandler.pauseAudio();
          break;
        case 'resume':
          await this.openAIHandler.resumeAudio();
          break;
        case 'clear':
          await this.openAIHandler.clearAudioBuffer();
          break;
      }

      this.sendMessage({
        type: 'audio.control.ack',
        timestamp: Date.now(),
        data: {
          action: data.action,
          success: true
        }
      });

    } catch (error) {
      this.logger.error('Audio control failed:', error);
      this.sendError('AUDIO_CONTROL_FAILED', 'Failed to control audio');
    }
  }

  public async handleConversationInterrupt(data: any): Promise<void> {
    if (!this.openAIHandler) {
      this.sendError('NO_SESSION', 'No active session');
      return;
    }

    try {
      await this.openAIHandler.interrupt(data.reason);
      
      this.sendMessage({
        type: 'conversation.interrupted',
        timestamp: Date.now(),
        data: {
          reason: data.reason
        }
      });

    } catch (error) {
      this.logger.error('Failed to interrupt conversation:', error);
      this.sendError('INTERRUPT_FAILED', 'Failed to interrupt conversation');
    }
  }

  public sendMessage(message: WebSocketMessage): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  private sendAudioStream(audioData: Buffer): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      // Convert to base64 for JSON transport
      const base64 = audioData.toString('base64');
      
      this.sendMessage({
        type: 'audio.stream',
        timestamp: Date.now(),
        data: {
          audio: base64,
          format: 'pcm16',
          sampleRate: 24000,
          channels: 1
        }
      });
    }
  }

  public sendError(code: string, message: string): void {
    this.sendMessage({
      type: 'error',
      timestamp: Date.now(),
      data: {
        code,
        message,
        severity: 'error'
      }
    });
  }

  public async cleanup(): Promise<void> {
    this.logger.info('Cleaning up client handler');

    // Close OpenAI connection
    if (this.openAIHandler) {
      await this.openAIHandler.disconnect();
      this.openAIHandler = null;
    }

    // Update session
    if (this.sessionId) {
      await this.sessionManager.updateSession(this.sessionId, {
        status: 'disconnected',
        disconnectedAt: new Date()
      });
    }

    // Remove all listeners
    this.removeAllListeners();
  }

  public async close(code: number, reason: string): Promise<void> {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.close(code, reason);
    }
    await this.cleanup();
  }

  public getClientId(): string {
    return this.clientId;
  }

  public getSessionId(): string | null {
    return this.sessionId;
  }

  public isConnected(): boolean {
    return this.ws.readyState === WebSocket.OPEN;
  }
}