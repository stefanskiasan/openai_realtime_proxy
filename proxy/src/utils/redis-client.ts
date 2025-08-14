import { createClient, RedisClientType } from 'redis';
import { Logger } from './logger';
import { Config } from '../config/config';

export class RedisClient {
  private static instance: RedisClient;
  private client: RedisClientType;
  private logger: Logger;
  private config: Config;
  private isConnected: boolean = false;

  private constructor() {
    this.logger = new Logger('RedisClient');
    this.config = Config.getInstance();
    
    this.client = createClient(this.config.getRedisConfig());
    
    this.setupEventHandlers();
  }

  public static getInstance(): RedisClient {
    if (!RedisClient.instance) {
      RedisClient.instance = new RedisClient();
    }
    return RedisClient.instance;
  }

  private setupEventHandlers(): void {
    this.client.on('error', (error) => {
      this.logger.error('Redis error:', error);
      this.isConnected = false;
    });

    this.client.on('connect', () => {
      this.logger.info('Redis connected');
      this.isConnected = true;
    });

    this.client.on('reconnecting', () => {
      this.logger.info('Redis reconnecting...');
    });

    this.client.on('ready', () => {
      this.logger.info('Redis ready');
      this.isConnected = true;
    });
  }

  public async connect(): Promise<void> {
    if (!this.isConnected) {
      await this.client.connect();
    }
  }

  public async disconnect(): Promise<void> {
    if (this.isConnected) {
      await this.client.quit();
      this.isConnected = false;
    }
  }

  public getClient(): RedisClientType {
    if (!this.isConnected) {
      throw new Error('Redis client is not connected');
    }
    return this.client;
  }

  // Session management methods
  public async setSession(sessionId: string, data: any, ttl?: number): Promise<void> {
    const key = `session:${sessionId}`;
    const value = JSON.stringify(data);
    
    if (ttl) {
      await this.client.setEx(key, ttl, value);
    } else {
      await this.client.set(key, value);
    }
  }

  public async getSession(sessionId: string): Promise<any | null> {
    const key = `session:${sessionId}`;
    const value = await this.client.get(key);
    
    if (value) {
      return JSON.parse(value);
    }
    
    return null;
  }

  public async deleteSession(sessionId: string): Promise<void> {
    const key = `session:${sessionId}`;
    await this.client.del(key);
  }

  public async extendSession(sessionId: string, ttl: number): Promise<void> {
    const key = `session:${sessionId}`;
    await this.client.expire(key, ttl);
  }

  // Function registry methods
  public async registerFunction(sessionId: string, functionName: string, schema: any): Promise<void> {
    const key = `function:${sessionId}:${functionName}`;
    const value = JSON.stringify(schema);
    await this.client.set(key, value);
    
    // Add to session's function index
    const indexKey = `session:${sessionId}:functions`;
    await this.client.sAdd(indexKey, functionName);
  }

  public async getFunction(sessionId: string, functionName: string): Promise<any | null> {
    const key = `function:${sessionId}:${functionName}`;
    const value = await this.client.get(key);
    
    if (value) {
      return JSON.parse(value);
    }
    
    return null;
  }

  public async getFunctions(sessionId: string): Promise<string[]> {
    const indexKey = `session:${sessionId}:functions`;
    return await this.client.sMembers(indexKey);
  }

  public async unregisterFunction(sessionId: string, functionName: string): Promise<void> {
    const key = `function:${sessionId}:${functionName}`;
    await this.client.del(key);
    
    const indexKey = `session:${sessionId}:functions`;
    await this.client.sRem(indexKey, functionName);
  }

  // Rate limiting methods
  public async checkRateLimit(identifier: string, limit: number, window: number): Promise<boolean> {
    const key = `ratelimit:${identifier}`;
    const current = await this.client.incr(key);
    
    if (current === 1) {
      await this.client.expire(key, window);
    }
    
    return current <= limit;
  }

  public async getRateLimitInfo(identifier: string): Promise<{ count: number; ttl: number }> {
    const key = `ratelimit:${identifier}`;
    const count = await this.client.get(key);
    const ttl = await this.client.ttl(key);
    
    return {
      count: count ? parseInt(count) : 0,
      ttl: ttl > 0 ? ttl : 0
    };
  }

  // Pub/Sub methods for scaling
  public async publish(channel: string, message: any): Promise<void> {
    await this.client.publish(channel, JSON.stringify(message));
  }

  public async subscribe(channel: string, handler: (message: any) => void): Promise<void> {
    const subscriber = this.client.duplicate();
    await subscriber.connect();
    
    await subscriber.subscribe(channel, (message) => {
      try {
        const parsed = JSON.parse(message);
        handler(parsed);
      } catch (error) {
        this.logger.error('Failed to parse subscription message:', error);
      }
    });
  }

  // Metrics methods
  public async incrementMetric(name: string, value: number = 1): Promise<void> {
    const key = `metric:${name}`;
    await this.client.incrBy(key, value);
  }

  public async getMetric(name: string): Promise<number> {
    const key = `metric:${name}`;
    const value = await this.client.get(key);
    return value ? parseInt(value) : 0;
  }

  // Health check
  public async ping(): Promise<boolean> {
    try {
      const response = await this.client.ping();
      return response === 'PONG';
    } catch (error) {
      return false;
    }
  }
}