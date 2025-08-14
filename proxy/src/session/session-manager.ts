import { Logger } from '../utils/logger';
import { RedisClient } from '../utils/redis-client';
import { Config } from '../config/config';
import { v4 as uuidv4 } from 'uuid';

export interface Session {
  id: string;
  clientId: string;
  clientIp: string;
  openAISessionId?: string;
  status: 'active' | 'inactive' | 'disconnected';
  created: Date;
  lastActivity: Date;
  disconnectedAt?: Date;
  config: any;
  functionCalls?: Record<string, number>;
  totalFunctionCalls?: number;
  audioInSeconds?: number;
  audioOutSeconds?: number;
  errors?: number;
}

export class SessionManager {
  private static instance: SessionManager;
  private logger: Logger;
  private redis: RedisClient;
  private config: Config;
  private sessions: Map<string, Session>;
  private sessionTimeout: number;

  private constructor() {
    this.logger = new Logger('SessionManager');
    this.redis = RedisClient.getInstance();
    this.config = Config.getInstance();
    this.sessions = new Map();
    this.sessionTimeout = this.config.get('SESSION_TIMEOUT') || 3600000; // 1 hour default

    // Start cleanup interval
    this.startCleanupInterval();
  }

  public static getInstance(): SessionManager {
    if (!SessionManager.instance) {
      SessionManager.instance = new SessionManager();
    }
    return SessionManager.instance;
  }

  public async createSession(
    sessionId: string,
    data: Partial<Session>
  ): Promise<Session> {
    const session: Session = {
      id: sessionId,
      clientId: data.clientId || uuidv4(),
      clientIp: data.clientIp || 'unknown',
      status: 'active',
      created: new Date(),
      lastActivity: new Date(),
      config: data.config || {},
      functionCalls: {},
      totalFunctionCalls: 0,
      audioInSeconds: 0,
      audioOutSeconds: 0,
      errors: 0,
      ...data
    };

    // Store in memory
    this.sessions.set(sessionId, session);

    // Store in Redis with TTL
    await this.redis.setSession(sessionId, session, this.sessionTimeout / 1000);

    // Update metrics
    await this.redis.incrementMetric('total_sessions');
    await this.redis.incrementMetric('active_sessions');

    this.logger.info(`Session created: ${sessionId}`);

    return session;
  }

  public async getSession(sessionId: string): Promise<Session | null> {
    // Check memory cache first
    let session = this.sessions.get(sessionId);
    
    if (!session) {
      // Try to load from Redis
      session = await this.redis.getSession(sessionId);
      
      if (session) {
        // Restore to memory cache
        this.sessions.set(sessionId, session);
      }
    }

    if (session) {
      // Update last activity
      session.lastActivity = new Date();
      await this.updateSession(sessionId, { lastActivity: session.lastActivity });
    }

    return session;
  }

  public async updateSession(
    sessionId: string,
    updates: Partial<Session>
  ): Promise<Session | null> {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      return null;
    }

    // Apply updates
    Object.assign(session, updates);
    session.lastActivity = new Date();

    // Update in memory
    this.sessions.set(sessionId, session);

    // Update in Redis
    await this.redis.setSession(sessionId, session, this.sessionTimeout / 1000);

    // Extend TTL
    await this.redis.extendSession(sessionId, this.sessionTimeout / 1000);

    return session;
  }

  public async deleteSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    
    // Remove from memory
    this.sessions.delete(sessionId);

    // Remove from Redis
    await this.redis.deleteSession(sessionId);

    // Clean up associated data
    const functions = await this.redis.getFunctions(sessionId);
    for (const func of functions) {
      await this.redis.unregisterFunction(sessionId, func);
    }

    // Update metrics
    if (session && session.status === 'active') {
      await this.redis.incrementMetric('active_sessions', -1);
    }

    this.logger.info(`Session deleted: ${sessionId}`);
  }

  public async recordFunctionCall(
    sessionId: string,
    functionName: string,
    success: boolean,
    executionTime?: number
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      return;
    }

    // Update function call counts
    if (!session.functionCalls) {
      session.functionCalls = {};
    }
    
    session.functionCalls[functionName] = (session.functionCalls[functionName] || 0) + 1;
    session.totalFunctionCalls = (session.totalFunctionCalls || 0) + 1;

    if (!success) {
      session.errors = (session.errors || 0) + 1;
    }

    await this.updateSession(sessionId, session);
  }

  public async recordAudioMetrics(
    sessionId: string,
    type: 'in' | 'out',
    seconds: number
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      return;
    }

    if (type === 'in') {
      session.audioInSeconds = (session.audioInSeconds || 0) + seconds;
    } else {
      session.audioOutSeconds = (session.audioOutSeconds || 0) + seconds;
    }

    await this.updateSession(sessionId, session);

    // Update global metrics
    await this.redis.incrementMetric('audio_minutes', seconds / 60);
  }

  public async getActiveSessions(): Promise<Session[]> {
    const sessions: Session[] = [];
    
    for (const session of this.sessions.values()) {
      if (session.status === 'active') {
        sessions.push(session);
      }
    }

    return sessions;
  }

  public async getSessionsByClient(clientId: string): Promise<Session[]> {
    const sessions: Session[] = [];
    
    for (const session of this.sessions.values()) {
      if (session.clientId === clientId) {
        sessions.push(session);
      }
    }

    return sessions;
  }

  public async cleanupExpiredSessions(): Promise<number> {
    const now = Date.now();
    let cleaned = 0;

    for (const [sessionId, session] of this.sessions) {
      const lastActivity = new Date(session.lastActivity).getTime();
      const age = now - lastActivity;

      if (age > this.sessionTimeout) {
        await this.deleteSession(sessionId);
        cleaned++;
        this.logger.info(`Cleaned up expired session: ${sessionId}`);
      }
    }

    return cleaned;
  }

  private startCleanupInterval(): void {
    // Run cleanup every 5 minutes
    setInterval(async () => {
      try {
        const cleaned = await this.cleanupExpiredSessions();
        
        if (cleaned > 0) {
          this.logger.info(`Cleaned up ${cleaned} expired sessions`);
        }
      } catch (error) {
        this.logger.error('Session cleanup error:', error);
      }
    }, 5 * 60 * 1000);
  }

  public async getStatistics(): Promise<any> {
    const activeSessions = await this.getActiveSessions();
    
    return {
      totalSessions: await this.redis.getMetric('total_sessions'),
      activeSessions: activeSessions.length,
      totalFunctionCalls: await this.redis.getMetric('function_calls'),
      totalAudioMinutes: await this.redis.getMetric('audio_minutes'),
      averageSessionDuration: this.calculateAverageSessionDuration(activeSessions),
      sessionsPerClient: this.getSessionsPerClient(activeSessions)
    };
  }

  private calculateAverageSessionDuration(sessions: Session[]): number {
    if (sessions.length === 0) {
      return 0;
    }

    const now = Date.now();
    let totalDuration = 0;

    for (const session of sessions) {
      const created = new Date(session.created).getTime();
      totalDuration += (now - created);
    }

    return totalDuration / sessions.length / 1000; // Return in seconds
  }

  private getSessionsPerClient(sessions: Session[]): Record<string, number> {
    const perClient: Record<string, number> = {};
    
    for (const session of sessions) {
      perClient[session.clientId] = (perClient[session.clientId] || 0) + 1;
    }

    return perClient;
  }

  public async enforceMaxSessions(): Promise<boolean> {
    const maxSessions = this.config.get('MAX_SESSIONS') || 1000;
    const activeSessions = await this.getActiveSessions();

    if (activeSessions.length >= maxSessions) {
      this.logger.warn(`Max sessions limit reached: ${maxSessions}`);
      return false;
    }

    return true;
  }

  public async getSessionLoad(): Promise<number> {
    const maxSessions = this.config.get('MAX_SESSIONS') || 1000;
    const activeSessions = await this.getActiveSessions();
    
    return (activeSessions.length / maxSessions) * 100;
  }
}