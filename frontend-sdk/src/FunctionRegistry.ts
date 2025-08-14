import { FunctionSchema } from './types';

export interface RegisteredFunction {
  name: string;
  handler: Function;
  schema?: FunctionSchema;
  timeout?: number;
}

export class FunctionRegistry {
  private functions: Map<string, RegisteredFunction>;
  private executionStats: Map<string, {
    calls: number;
    errors: number;
    totalTime: number;
    lastCall?: Date;
  }>;

  constructor() {
    this.functions = new Map();
    this.executionStats = new Map();
  }

  public register(
    name: string,
    handler: Function,
    schema?: FunctionSchema
  ): void {
    if (typeof name !== 'string' || name.length === 0) {
      throw new Error('Function name must be a non-empty string');
    }

    if (typeof handler !== 'function') {
      throw new Error('Handler must be a function');
    }

    // Validate function name format
    if (!/^[a-zA-Z0-9_]+$/.test(name)) {
      throw new Error('Function name must contain only alphanumeric characters and underscores');
    }

    this.functions.set(name, {
      name,
      handler,
      schema,
      timeout: schema?.timeout || 10000
    });

    // Initialize stats
    if (!this.executionStats.has(name)) {
      this.executionStats.set(name, {
        calls: 0,
        errors: 0,
        totalTime: 0
      });
    }

    console.log(`Function registered: ${name}`);
  }

  public unregister(name: string): boolean {
    const deleted = this.functions.delete(name);
    
    if (deleted) {
      console.log(`Function unregistered: ${name}`);
    }
    
    return deleted;
  }

  public async execute(name: string, args: any): Promise<any> {
    const func = this.functions.get(name);
    
    if (!func) {
      throw new Error(`Function '${name}' not found`);
    }

    const startTime = performance.now();
    const stats = this.executionStats.get(name)!;
    stats.calls++;
    stats.lastCall = new Date();

    try {
      // Execute with timeout
      const result = await this.executeWithTimeout(
        func.handler,
        args,
        func.timeout || 10000
      );

      // Update stats
      const executionTime = performance.now() - startTime;
      stats.totalTime += executionTime;

      return result;

    } catch (error) {
      // Update error stats
      stats.errors++;
      
      console.error(`Function '${name}' execution failed:`, error);
      throw error;
    }
  }

  private executeWithTimeout(
    handler: Function,
    args: any,
    timeout: number
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      let timeoutId: NodeJS.Timeout;

      // Create timeout promise
      const timeoutPromise = new Promise((_, timeoutReject) => {
        timeoutId = setTimeout(() => {
          timeoutReject(new Error(`Function execution timeout (${timeout}ms)`));
        }, timeout);
      });

      // Execute function
      const executionPromise = Promise.resolve(handler(args));

      // Race between execution and timeout
      Promise.race([executionPromise, timeoutPromise])
        .then(result => {
          clearTimeout(timeoutId);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timeoutId);
          reject(error);
        });
    });
  }

  public has(name: string): boolean {
    return this.functions.has(name);
  }

  public get(name: string): RegisteredFunction | undefined {
    return this.functions.get(name);
  }

  public getAll(): RegisteredFunction[] {
    return Array.from(this.functions.values());
  }

  public getAllNames(): string[] {
    return Array.from(this.functions.keys());
  }

  public getSchema(name: string): FunctionSchema | undefined {
    return this.functions.get(name)?.schema;
  }

  public clear(): void {
    this.functions.clear();
    this.executionStats.clear();
    console.log('All functions cleared');
  }

  public getStatistics(name?: string): any {
    if (name) {
      const stats = this.executionStats.get(name);
      
      if (!stats) {
        return null;
      }

      return {
        name,
        calls: stats.calls,
        errors: stats.errors,
        errorRate: stats.calls > 0 ? stats.errors / stats.calls : 0,
        avgExecutionTime: stats.calls > 0 ? stats.totalTime / stats.calls : 0,
        totalTime: stats.totalTime,
        lastCall: stats.lastCall
      };
    }

    // Return all statistics
    const allStats: any[] = [];
    
    for (const [funcName, stats] of this.executionStats) {
      allStats.push({
        name: funcName,
        calls: stats.calls,
        errors: stats.errors,
        errorRate: stats.calls > 0 ? stats.errors / stats.calls : 0,
        avgExecutionTime: stats.calls > 0 ? stats.totalTime / stats.calls : 0,
        totalTime: stats.totalTime,
        lastCall: stats.lastCall
      });
    }

    return {
      totalFunctions: this.functions.size,
      totalCalls: allStats.reduce((sum, s) => sum + s.calls, 0),
      totalErrors: allStats.reduce((sum, s) => sum + s.errors, 0),
      functions: allStats
    };
  }

  public validateArguments(name: string, args: any): boolean {
    const func = this.functions.get(name);
    
    if (!func || !func.schema?.parameters) {
      return true; // No schema to validate against
    }

    // Basic validation - could be enhanced with a JSON Schema validator
    const params = func.schema.parameters;
    
    if (params.type === 'object' && params.properties) {
      // Check required properties
      if (params.required) {
        for (const required of params.required) {
          if (!(required in args)) {
            console.error(`Missing required argument: ${required}`);
            return false;
          }
        }
      }

      // Check property types
      for (const [key, prop] of Object.entries(params.properties)) {
        if (key in args) {
          const expectedType = (prop as any).type;
          const actualType = typeof args[key];

          if (expectedType && actualType !== expectedType) {
            console.error(`Type mismatch for ${key}: expected ${expectedType}, got ${actualType}`);
            return false;
          }
        }
      }
    }

    return true;
  }

  public toJSON(): any {
    const functions: any[] = [];
    
    for (const func of this.functions.values()) {
      functions.push({
        name: func.name,
        schema: func.schema,
        timeout: func.timeout
      });
    }

    return functions;
  }

  public fromJSON(data: any[]): void {
    // Note: This cannot restore the actual handler functions
    // It's mainly useful for reconstructing the registry structure
    console.warn('fromJSON cannot restore function handlers, only metadata');
    
    for (const item of data) {
      if (item.name && !this.functions.has(item.name)) {
        // Create a placeholder function
        this.functions.set(item.name, {
          name: item.name,
          handler: () => {
            throw new Error(`Function ${item.name} handler not restored`);
          },
          schema: item.schema,
          timeout: item.timeout
        });
      }
    }
  }
}