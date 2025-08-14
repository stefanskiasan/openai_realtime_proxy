export interface VoiceChatConfig {
  url: string;
  token?: string;
  autoReconnect?: boolean;
  debug?: boolean;
  model?: string;
  voice?: string;
  temperature?: number;
  language?: string;
  audioConfig?: AudioConfig;
}

export interface AudioConfig {
  sampleRate?: number;
  channels?: number;
  echoCancellation?: boolean;
  noiseSuppression?: boolean;
  autoGainControl?: boolean;
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

export interface WebSocketMessage {
  type: string;
  id?: string;
  timestamp: number;
  data: any;
  version?: string;
}

export interface FunctionCall {
  callId?: string;
  name: string;
  arguments: any;
  timeout?: number;
}

export interface FunctionResult {
  callId?: string;
  success: boolean;
  result?: any;
  error?: {
    code: string;
    message: string;
  };
}

export interface FunctionSchema {
  name: string;
  description?: string;
  parameters?: any;
  returns?: any;
  version?: string;
  timeout?: number;
}

export interface SessionData {
  sessionId: string;
  status: string;
  created: string;
  config?: any;
}

export interface TranscriptionData {
  text: string;
  isFinal: boolean;
  confidence?: number;
  language?: string;
  speaker?: string;
}

export interface ResponseData {
  text: string;
  delta?: string;
  isComplete: boolean;
  turnId?: string;
}

export interface StatusData {
  state: 'idle' | 'listening' | 'processing' | 'speaking' | 'thinking';
  details?: string;
  progress?: number;
}