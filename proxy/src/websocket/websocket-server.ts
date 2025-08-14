import { Server as HTTPServer } from 'http';
import { WebSocket, WebSocketServer as WSServer } from 'ws';
import { Logger } from '../utils/logger';
import { Config } from '../config/config';
import { ClientHandler } from './client-handler';
import { v4 as uuidv4 } from 'uuid';

export class WebSocketServer {
  private wss: WSServer;
  private logger: Logger;
  private config: Config;
  private clients: Map<string, ClientHandler>;
  private httpServer: HTTPServer;

  constructor(httpServer: HTTPServer) {
    this.logger = new Logger('WebSocketServer');
    this.config = Config.getInstance();
    this.clients = new Map();
    this.httpServer = httpServer;
    
    const wsPath = this.config.get('WS_PATH') || '/ws';
    
    this.wss = new WSServer({
      server: httpServer,
      path: wsPath,
      perMessageDeflate: {
        zlibDeflateOptions: {
          chunkSize: 1024,
          memLevel: 7,
          level: 3
        },
        zlibInflateOptions: {
          chunkSize: 10 * 1024
        },
        clientNoContextTakeover: true,
        serverNoContextTakeover: true,
        serverMaxWindowBits: 10,
        concurrencyLimit: 10,
        threshold: 1024
      },
      maxPayload: 10 * 1024 * 1024 // 10MB max message size
    });
  }

  public async initialize(): Promise<void> {
    this.setupEventHandlers();
    this.logger.info('WebSocket server initialized');
  }

  private setupEventHandlers(): void {
    this.wss.on('connection', (ws: WebSocket, request) => {
      const clientId = uuidv4();
      const clientIp = this.getClientIp(request);
      
      this.logger.info(`New WebSocket connection from ${clientIp}`, { clientId });
      
      // Create client handler
      const clientHandler = new ClientHandler(ws, clientId, clientIp);
      this.clients.set(clientId, clientHandler);
      
      // Send welcome message
      clientHandler.sendMessage({
        type: 'system.welcome',
        timestamp: Date.now(),
        data: {
          sessionId: clientId,
          protocolVersion: '1.0',
          serverVersion: '1.0.0',
          features: ['audio', 'functions', 'interrupts'],
          limits: {
            maxFunctions: 50,
            maxAudioDuration: 3600,
            maxMessageSize: 10 * 1024 * 1024
          }
        }
      });
      
      // Handle client disconnection
      ws.on('close', (code, reason) => {
        this.logger.info(`Client disconnected: ${clientId}`, { code, reason: reason?.toString() });
        this.handleClientDisconnect(clientId);
      });
      
      ws.on('error', (error) => {
        this.logger.error(`WebSocket error for client ${clientId}:`, error);
      });
      
      // Setup ping/pong for keep-alive
      this.setupKeepAlive(ws, clientId);
    });
    
    this.wss.on('error', (error) => {
      this.logger.error('WebSocket server error:', error);
    });
  }

  private getClientIp(request: any): string {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
    return request.socket.remoteAddress || 'unknown';
  }

  private setupKeepAlive(ws: WebSocket, clientId: string): void {
    let isAlive = true;
    
    ws.on('pong', () => {
      isAlive = true;
    });
    
    const interval = setInterval(() => {
      if (!isAlive) {
        this.logger.warn(`Client ${clientId} failed to respond to ping, terminating connection`);
        ws.terminate();
        clearInterval(interval);
        return;
      }
      
      isAlive = false;
      ws.ping();
    }, 30000); // Ping every 30 seconds
    
    ws.on('close', () => {
      clearInterval(interval);
    });
  }

  private async handleClientDisconnect(clientId: string): Promise<void> {
    const client = this.clients.get(clientId);
    
    if (client) {
      await client.cleanup();
      this.clients.delete(clientId);
    }
    
    this.logger.info(`Client ${clientId} cleaned up, active clients: ${this.clients.size}`);
  }

  public async shutdown(): Promise<void> {
    this.logger.info('Shutting down WebSocket server...');
    
    // Close all client connections
    for (const [clientId, client] of this.clients) {
      await client.close(1000, 'Server shutting down');
    }
    
    // Close WebSocket server
    return new Promise((resolve) => {
      this.wss.close(() => {
        this.logger.info('WebSocket server closed');
        resolve();
      });
    });
  }

  public getActiveConnections(): number {
    return this.clients.size;
  }

  public getClient(clientId: string): ClientHandler | undefined {
    return this.clients.get(clientId);
  }
}