import { Logger } from '../utils/logger';
import { ClientHandler } from './client-handler';
import { WebSocketMessage } from '../types';

export class MessageRouter {
  private logger: Logger;
  private clientHandler: ClientHandler;
  private messageHandlers: Map<string, (message: WebSocketMessage) => Promise<void>>;

  constructor(clientHandler: ClientHandler) {
    this.logger = new Logger('MessageRouter');
    this.clientHandler = clientHandler;
    this.messageHandlers = new Map();

    this.registerHandlers();
  }

  private registerHandlers(): void {
    // Session management
    this.messageHandlers.set('session.init', async (msg) => {
      await this.clientHandler.handleSessionInit(msg.data.config);
    });

    this.messageHandlers.set('session.resume', async (msg) => {
      await this.clientHandler.handleSessionResume(msg.data.sessionId);
    });

    // Function registry
    this.messageHandlers.set('function.register', async (msg) => {
      await this.clientHandler.handleFunctionRegister(msg.data);
    });

    this.messageHandlers.set('function.unregister', async (msg) => {
      await this.clientHandler.handleFunctionUnregister(msg.data);
    });

    this.messageHandlers.set('function.update', async (msg) => {
      // TODO: Implement function update
      this.logger.warn('Function update not yet implemented');
    });

    this.messageHandlers.set('function.result', (msg) => {
      this.clientHandler.handleFunctionResult(msg);
      return Promise.resolve();
    });

    // Audio control
    this.messageHandlers.set('audio.stream', async (msg) => {
      // Audio streaming is handled separately in handleBinaryAudio
      this.logger.debug('Audio stream message received');
    });

    this.messageHandlers.set('audio.control', async (msg) => {
      await this.clientHandler.handleAudioControl(msg.data);
    });

    // Conversation control
    this.messageHandlers.set('conversation.interrupt', async (msg) => {
      await this.clientHandler.handleConversationInterrupt(msg.data);
    });

    // System messages
    this.messageHandlers.set('system.ping', (msg) => {
      this.clientHandler.sendMessage({
        type: 'system.pong',
        timestamp: Date.now(),
        data: {
          sequence: msg.data.sequence,
          serverTime: Date.now()
        }
      });
      return Promise.resolve();
    });

    // Authentication
    this.messageHandlers.set('auth.token', async (msg) => {
      // TODO: Implement authentication
      this.logger.warn('Authentication not yet implemented');
      this.clientHandler.sendMessage({
        type: 'auth.success',
        timestamp: Date.now(),
        data: {
          authenticated: true
        }
      });
    });
  }

  public async route(message: WebSocketMessage): Promise<void> {
    const handler = this.messageHandlers.get(message.type);

    if (handler) {
      try {
        await handler(message);
      } catch (error) {
        this.logger.error(`Error handling message type ${message.type}:`, error);
        this.clientHandler.sendError(
          'MESSAGE_HANDLER_ERROR',
          `Failed to handle message type: ${message.type}`
        );
      }
    } else {
      this.logger.warn(`Unknown message type: ${message.type}`);
      this.clientHandler.sendError(
        'UNKNOWN_MESSAGE_TYPE',
        `Unknown message type: ${message.type}`
      );
    }
  }

  public registerCustomHandler(
    type: string,
    handler: (message: WebSocketMessage) => Promise<void>
  ): void {
    this.messageHandlers.set(type, handler);
    this.logger.info(`Registered custom handler for message type: ${type}`);
  }

  public unregisterHandler(type: string): boolean {
    const deleted = this.messageHandlers.delete(type);
    
    if (deleted) {
      this.logger.info(`Unregistered handler for message type: ${type}`);
    }
    
    return deleted;
  }

  public getRegisteredTypes(): string[] {
    return Array.from(this.messageHandlers.keys());
  }

  public hasHandler(type: string): boolean {
    return this.messageHandlers.has(type);
  }
}