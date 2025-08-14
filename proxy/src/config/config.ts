import { CorsOptions } from 'cors';

export class Config {
  private static instance: Config;
  private config: Map<string, any>;

  private constructor() {
    this.config = new Map();
    this.loadEnvironmentVariables();
  }

  public static getInstance(): Config {
    if (!Config.instance) {
      Config.instance = new Config();
    }
    return Config.instance;
  }

  private loadEnvironmentVariables(): void {
    // Server configuration
    this.config.set('NODE_ENV', process.env.NODE_ENV || 'development');
    this.config.set('PORT', parseInt(process.env.PORT || '8080'));
    this.config.set('WS_PATH', process.env.WS_PATH || '/ws');
    
    // OpenAI configuration
    this.config.set('OPENAI_API_KEY', process.env.OPENAI_API_KEY);
    this.config.set('OPENAI_ORG_ID', process.env.OPENAI_ORG_ID);
    
    // Redis configuration
    this.config.set('REDIS_URL', process.env.REDIS_URL || 'redis://localhost:6379');
    this.config.set('REDIS_PASSWORD', process.env.REDIS_PASSWORD);
    
    // Session configuration
    this.config.set('MAX_SESSIONS', parseInt(process.env.MAX_SESSIONS || '1000'));
    this.config.set('SESSION_TIMEOUT', parseInt(process.env.SESSION_TIMEOUT || '3600000'));
    
    // Security configuration
    this.config.set('JWT_SECRET', process.env.JWT_SECRET || 'change-this-secret');
    this.config.set('API_KEY', process.env.API_KEY);
    
    // CORS configuration
    this.config.set('ENABLE_CORS', process.env.ENABLE_CORS === 'true');
    this.config.set('CORS_ORIGIN', process.env.CORS_ORIGIN || '*');
    
    // Rate limiting
    this.config.set('RATE_LIMIT_WINDOW', parseInt(process.env.RATE_LIMIT_WINDOW || '60000'));
    this.config.set('RATE_LIMIT_MAX_REQUESTS', parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'));
    
    // Logging
    this.config.set('LOG_LEVEL', process.env.LOG_LEVEL || 'info');
    
    // Monitoring
    this.config.set('METRICS_ENABLED', process.env.METRICS_ENABLED === 'true');
    this.config.set('PROMETHEUS_PORT', parseInt(process.env.PROMETHEUS_PORT || '9091'));
  }

  public get(key: string): any {
    return this.config.get(key);
  }

  public set(key: string, value: any): void {
    this.config.set(key, value);
  }

  public getCorsOptions(): CorsOptions {
    const origin = this.get('CORS_ORIGIN');
    
    return {
      origin: origin === '*' ? true : origin.split(','),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
      exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining'],
      maxAge: 86400
    };
  }

  public getRedisConfig(): any {
    const url = this.get('REDIS_URL');
    const password = this.get('REDIS_PASSWORD');
    
    return {
      url,
      password: password || undefined,
      retryStrategy: (times: number) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      }
    };
  }

  public isProduction(): boolean {
    return this.get('NODE_ENV') === 'production';
  }

  public isDevelopment(): boolean {
    return this.get('NODE_ENV') === 'development';
  }

  public validate(): void {
    const required = ['OPENAI_API_KEY'];
    const missing = required.filter(key => !this.get(key));
    
    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
  }
}