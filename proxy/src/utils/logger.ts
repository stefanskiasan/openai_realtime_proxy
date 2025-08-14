import winston from 'winston';
import { Config } from '../config/config';

const config = Config.getInstance();

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
    const contextStr = context ? `[${context}]` : '';
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
    return `${timestamp} ${level} ${contextStr} ${message} ${metaStr}`;
  })
);

export class Logger {
  private logger: winston.Logger;
  private context: string;

  constructor(context: string) {
    this.context = context;
    
    this.logger = winston.createLogger({
      level: config.get('LOG_LEVEL') || 'info',
      format: logFormat,
      defaultMeta: { context },
      transports: [
        new winston.transports.Console({
          format: config.isDevelopment() ? consoleFormat : logFormat
        })
      ]
    });

    if (config.isProduction()) {
      this.logger.add(new winston.transports.File({
        filename: 'logs/error.log',
        level: 'error'
      }));
      
      this.logger.add(new winston.transports.File({
        filename: 'logs/combined.log'
      }));
    }
  }

  info(message: string, meta?: any): void {
    this.logger.info(message, { context: this.context, ...meta });
  }

  error(message: string, error?: any, meta?: any): void {
    this.logger.error(message, { 
      context: this.context, 
      error: error?.stack || error?.message || error,
      ...meta 
    });
  }

  warn(message: string, meta?: any): void {
    this.logger.warn(message, { context: this.context, ...meta });
  }

  debug(message: string, meta?: any): void {
    this.logger.debug(message, { context: this.context, ...meta });
  }

  security(message: string, meta?: any): void {
    this.logger.warn(`[SECURITY] ${message}`, { 
      context: this.context, 
      type: 'security',
      ...meta 
    });
  }

  metric(name: string, value: number, meta?: any): void {
    this.logger.info('metric', {
      context: this.context,
      metric: name,
      value,
      ...meta
    });
  }
}