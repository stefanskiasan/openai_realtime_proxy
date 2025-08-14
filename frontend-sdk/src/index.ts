// Main exports for Voice Chat SDK
export { VoiceChatClient } from './VoiceChatClient';
export { AudioManager } from './AudioManager';
export { FunctionRegistry } from './FunctionRegistry';

// Type exports
export type {
  VoiceChatConfig,
  AudioConfig,
  ConnectionState,
  WebSocketMessage,
  FunctionCall,
  FunctionResult,
  FunctionSchema,
  SessionData,
  TranscriptionData,
  ResponseData,
  StatusData
} from './types';

// Version
export const VERSION = '1.0.0';