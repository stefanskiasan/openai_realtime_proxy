import { Logger } from '../utils/logger';
import { RedisClient } from '../utils/redis-client';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

export interface FunctionSchema {
  name: string;
  description?: string;
  parameters?: any;
  returns?: any;
  version?: string;
  timeout?: number;
  retryPolicy?: {
    maxRetries: number;
    retryDelay: number;
  };
  permissions?: string[];
  rateLimit?: {
    maxCalls: number;
    window: number;
  };
}

export interface RegisteredFunction extends FunctionSchema {
  sessionId: string;
  registeredAt: Date;
  lastCalled?: Date;
  callCount: number;
  avgExecutionTime?: number;
  errorCount: number;
}

export class FunctionRegistry {
  private logger: Logger;
  private redis: RedisClient;
  private ajv: Ajv;

  constructor() {
    this.logger = new Logger('FunctionRegistry');
    this.redis = RedisClient.getInstance();
    
    // Initialize JSON Schema validator
    this.ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(this.ajv);
    
    // Add custom format for safe strings
    this.ajv.addFormat('safe-string', {
      type: 'string',
      validate: (data: string) => {
        // Check for injection patterns
        const sqlPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)/gi;
        const noSqlPatterns = /(\$\w+:|{"\$)/;
        const cmdPatterns = /(;|\||&&|\$\(|`)/;
        
        return !sqlPatterns.test(data) && 
               !noSqlPatterns.test(data) && 
               !cmdPatterns.test(data);
      }
    });
  }

  public async register(
    sessionId: string, 
    name: string, 
    schema: FunctionSchema
  ): Promise<RegisteredFunction> {
    // Validate function name
    if (!this.isValidFunctionName(name)) {
      throw new Error('Invalid function name. Use only alphanumeric characters and underscores.');
    }

    // Validate schema
    if (schema.parameters && !this.validateParameters(schema.parameters)) {
      throw new Error('Invalid function parameters schema');
    }

    const registeredFunction: RegisteredFunction = {
      ...schema,
      name,
      sessionId,
      registeredAt: new Date(),
      callCount: 0,
      errorCount: 0
    };

    // Store in Redis
    await this.redis.registerFunction(sessionId, name, registeredFunction);
    
    // Update metrics
    await this.redis.incrementMetric('functions_registered');

    this.logger.info(`Function registered: ${name} for session ${sessionId}`);
    
    return registeredFunction;
  }

  public async unregister(sessionId: string, name: string): Promise<void> {
    await this.redis.unregisterFunction(sessionId, name);
    await this.redis.incrementMetric('functions_unregistered');
    
    this.logger.info(`Function unregistered: ${name} for session ${sessionId}`);
  }

  public async getFunction(
    sessionId: string, 
    name: string
  ): Promise<RegisteredFunction | null> {
    const func = await this.redis.getFunction(sessionId, name);
    return func as RegisteredFunction | null;
  }

  public async getFunctions(sessionId: string): Promise<RegisteredFunction[]> {
    const functionNames = await this.redis.getFunctions(sessionId);
    const functions: RegisteredFunction[] = [];

    for (const name of functionNames) {
      const func = await this.getFunction(sessionId, name);
      if (func) {
        functions.push(func);
      }
    }

    return functions;
  }

  public async updateFunction(
    sessionId: string,
    name: string,
    updates: Partial<FunctionSchema>
  ): Promise<RegisteredFunction> {
    const existing = await this.getFunction(sessionId, name);
    
    if (!existing) {
      throw new Error('Function not found');
    }

    const updated: RegisteredFunction = {
      ...existing,
      ...updates,
      name, // Ensure name doesn't change
      sessionId, // Ensure sessionId doesn't change
      registeredAt: existing.registeredAt // Preserve registration time
    };

    await this.redis.registerFunction(sessionId, name, updated);
    
    this.logger.info(`Function updated: ${name} for session ${sessionId}`);
    
    return updated;
  }

  public convertToTool(func: FunctionSchema | RegisteredFunction): any {
    return {
      type: 'function',
      function: {
        name: func.name,
        description: func.description || `Function ${func.name}`,
        parameters: func.parameters || {
          type: 'object',
          properties: {}
        }
      }
    };
  }

  public async recordFunctionCall(
    sessionId: string,
    name: string,
    success: boolean,
    executionTime: number
  ): Promise<void> {
    const func = await this.getFunction(sessionId, name);
    
    if (!func) {
      return;
    }

    // Update function statistics
    func.callCount++;
    func.lastCalled = new Date();
    
    if (!success) {
      func.errorCount++;
    }

    // Calculate average execution time
    if (func.avgExecutionTime) {
      func.avgExecutionTime = 
        (func.avgExecutionTime * (func.callCount - 1) + executionTime) / func.callCount;
    } else {
      func.avgExecutionTime = executionTime;
    }

    await this.redis.registerFunction(sessionId, name, func);

    // Update global metrics
    await this.redis.incrementMetric('function_calls');
    if (!success) {
      await this.redis.incrementMetric('function_errors');
    }

    this.logger.debug(`Function call recorded: ${name}`, {
      success,
      executionTime,
      callCount: func.callCount
    });
  }

  public async checkRateLimit(
    sessionId: string,
    name: string
  ): Promise<boolean> {
    const func = await this.getFunction(sessionId, name);
    
    if (!func || !func.rateLimit) {
      return true; // No rate limit configured
    }

    const key = `${sessionId}:${name}`;
    const { maxCalls, window } = func.rateLimit;
    
    return await this.redis.checkRateLimit(key, maxCalls, window / 1000);
  }

  private isValidFunctionName(name: string): boolean {
    // Only allow alphanumeric characters and underscores
    const pattern = /^[a-zA-Z0-9_]+$/;
    return pattern.test(name) && name.length > 0 && name.length <= 100;
  }

  private validateParameters(parameters: any): boolean {
    try {
      // Compile schema to check if it's valid
      this.ajv.compile(parameters);
      return true;
    } catch (error) {
      this.logger.error('Invalid parameter schema:', error);
      return false;
    }
  }

  public validateFunctionArguments(
    schema: FunctionSchema,
    args: any
  ): { valid: boolean; errors?: any[] } {
    if (!schema.parameters) {
      return { valid: true };
    }

    const validate = this.ajv.compile(schema.parameters);
    const valid = validate(args);

    if (!valid) {
      return {
        valid: false,
        errors: validate.errors
      };
    }

    return { valid: true };
  }

  public async getAllFunctions(): Promise<Map<string, RegisteredFunction[]>> {
    // This would need to be implemented with proper Redis scanning
    // For now, return empty map
    return new Map();
  }

  public async cleanupExpiredFunctions(ttl: number = 86400000): Promise<number> {
    // Clean up functions older than TTL (default 24 hours)
    let cleaned = 0;
    
    // This would need to be implemented with proper Redis scanning
    // and checking timestamps
    
    this.logger.info(`Cleaned up ${cleaned} expired functions`);
    return cleaned;
  }

  public async getStatistics(sessionId?: string): Promise<any> {
    if (sessionId) {
      const functions = await this.getFunctions(sessionId);
      
      return {
        sessionId,
        totalFunctions: functions.length,
        totalCalls: functions.reduce((sum, f) => sum + f.callCount, 0),
        totalErrors: functions.reduce((sum, f) => sum + f.errorCount, 0),
        avgExecutionTime: functions.reduce((sum, f) => 
          sum + (f.avgExecutionTime || 0), 0) / functions.length || 0,
        functions: functions.map(f => ({
          name: f.name,
          callCount: f.callCount,
          errorCount: f.errorCount,
          avgExecutionTime: f.avgExecutionTime,
          lastCalled: f.lastCalled
        }))
      };
    }

    // Global statistics
    return {
      totalFunctionsRegistered: await this.redis.getMetric('functions_registered'),
      totalFunctionCalls: await this.redis.getMetric('function_calls'),
      totalFunctionErrors: await this.redis.getMetric('function_errors')
    };
  }
}