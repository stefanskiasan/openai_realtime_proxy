import { Express, Request, Response } from 'express';
import { RedisClient } from '../utils/redis-client';
import { Logger } from '../utils/logger';
import { Config } from '../config/config';

const logger = new Logger('Routes');
const config = Config.getInstance();

export function setupRoutes(app: Express): void {
  const redis = RedisClient.getInstance();

  // Health check endpoint
  app.get('/health', async (req: Request, res: Response) => {
    try {
      const redisHealthy = await redis.ping();
      
      const health = {
        status: redisHealthy ? 'healthy' : 'degraded',
        version: '1.0.0',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        connections: {
          redis: redisHealthy ? 'connected' : 'disconnected',
          openai: 'ready'
        },
        stats: {
          activeSessions: await redis.getMetric('active_sessions'),
          totalFunctionCalls: await redis.getMetric('function_calls'),
          audioMinutesProcessed: await redis.getMetric('audio_minutes')
        }
      };

      const statusCode = redisHealthy ? 200 : 503;
      res.status(statusCode).json(health);
    } catch (error) {
      logger.error('Health check failed:', error);
      res.status(503).json({
        status: 'unhealthy',
        error: 'Health check failed'
      });
    }
  });

  // Session information endpoint
  app.get('/api/session/:sessionId', async (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      
      // TODO: Add authentication check here
      
      const session = await redis.getSession(sessionId);
      
      if (!session) {
        return res.status(404).json({
          error: 'Session not found'
        });
      }

      const functions = await redis.getFunctions(sessionId);
      
      res.json({
        sessionId,
        status: session.status || 'active',
        created: session.created,
        lastActivity: session.lastActivity,
        functions: functions.map(name => ({
          name,
          callCount: session.functionCalls?.[name] || 0
        })),
        metrics: {
          audioInSeconds: session.audioInSeconds || 0,
          audioOutSeconds: session.audioOutSeconds || 0,
          functionCalls: session.totalFunctionCalls || 0,
          errors: session.errors || 0
        }
      });
    } catch (error) {
      logger.error('Failed to get session info:', error);
      res.status(500).json({
        error: 'Internal server error'
      });
    }
  });

  // List active sessions (admin only)
  app.get('/api/sessions', async (req: Request, res: Response) => {
    try {
      // TODO: Add admin authentication check here
      
      const limit = parseInt(req.query.limit as string) || 100;
      const offset = parseInt(req.query.offset as string) || 0;
      
      // This is a simplified version - in production, you'd want to maintain
      // a proper index of active sessions
      res.json({
        sessions: [],
        total: 0,
        limit,
        offset
      });
    } catch (error) {
      logger.error('Failed to list sessions:', error);
      res.status(500).json({
        error: 'Internal server error'
      });
    }
  });

  // Metrics endpoint (for Prometheus)
  if (config.get('METRICS_ENABLED')) {
    app.get('/metrics', async (req: Request, res: Response) => {
      try {
        const metrics = {
          active_sessions: await redis.getMetric('active_sessions'),
          total_sessions: await redis.getMetric('total_sessions'),
          function_calls: await redis.getMetric('function_calls'),
          function_errors: await redis.getMetric('function_errors'),
          audio_minutes: await redis.getMetric('audio_minutes'),
          websocket_connections: await redis.getMetric('websocket_connections'),
          api_requests: await redis.getMetric('api_requests'),
          api_errors: await redis.getMetric('api_errors')
        };

        // Format as Prometheus metrics
        const prometheusFormat = Object.entries(metrics)
          .map(([key, value]) => `voice_proxy_${key} ${value}`)
          .join('\n');

        res.set('Content-Type', 'text/plain');
        res.send(prometheusFormat);
      } catch (error) {
        logger.error('Failed to get metrics:', error);
        res.status(500).send('Failed to get metrics');
      }
    });
  }

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      error: 'Not found',
      path: req.path
    });
  });

  // Error handler
  app.use((error: any, req: Request, res: Response) => {
    logger.error('Unhandled error:', error);
    
    const statusCode = error.statusCode || 500;
    const message = config.isDevelopment() 
      ? error.message 
      : 'Internal server error';
    
    res.status(statusCode).json({
      error: message,
      ...(config.isDevelopment() && { stack: error.stack })
    });
  });
}