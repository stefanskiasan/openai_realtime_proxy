import express from 'express';
import { createServer } from 'http';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { WebSocketServer } from './websocket/websocket-server';
import { RedisClient } from './utils/redis-client';
import { Logger } from './utils/logger';
import { Config } from './config/config';
import { setupRoutes } from './routes';

// Load environment variables
dotenv.config();

const logger = new Logger('Server');
const config = Config.getInstance();

async function startServer() {
  try {
    // Initialize Express app
    const app = express();
    const httpServer = createServer(app);

    // Middleware
    app.use(helmet());
    app.use(cors(config.getCorsOptions()));
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));

    // Initialize Redis
    const redis = RedisClient.getInstance();
    await redis.connect();
    logger.info('Redis connected');

    // Setup routes
    setupRoutes(app);

    // Initialize WebSocket server
    const wsServer = new WebSocketServer(httpServer);
    await wsServer.initialize();
    logger.info('WebSocket server initialized');

    // Start HTTP server
    const port = config.get('PORT') || 8080;
    httpServer.listen(port, () => {
      logger.info(`Server running on port ${port}`);
      
      // Send ready signal to PM2
      if (process.send) {
        process.send('ready');
      }
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM received, shutting down gracefully');
      
      httpServer.close(() => {
        logger.info('HTTP server closed');
      });
      
      await wsServer.shutdown();
      await redis.disconnect();
      
      process.exit(0);
    });

    process.on('SIGINT', async () => {
      logger.info('SIGINT received, shutting down gracefully');
      
      httpServer.close(() => {
        logger.info('HTTP server closed');
      });
      
      await wsServer.shutdown();
      await redis.disconnect();
      
      process.exit(0);
    });

    // Unhandled rejection handler
    process.on('unhandledRejection', (reason, promise) => {
      logger.error(`Unhandled Rejection: ${reason}`);
    });

    // Uncaught exception handler
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      process.exit(1);
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();